"""Tests for the GitHub-to-Replit deployment sync control.

Covers:
* /api/status exposes git_commit, deployment_revision, policy_version,
  runtime_status.
* Mismatch between runtime commit and the expected GitHub main commit
  fails closed at startup with a structured audit event.
* Matching commit passes (successful sync).
* Unenforced mode (env unset) is a no-op so dev/test still boot.
* Logs and exception messages contain only commit SHAs and the
  deployment revision — no other env values or secrets.
"""
from __future__ import annotations

import logging

import pytest

from governance import deployment_sync as ds


VALID_SHA_A = "a" * 40
VALID_SHA_B = "b" * 40


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for name in (
        *ds.EXPECTED_COMMIT_ENV_VARS,
        *ds.DEPLOYMENT_REVISION_ENV_VARS,
    ):
        monkeypatch.delenv(name, raising=False)
    yield


def _force_runtime_commit(monkeypatch, sha: str | None) -> None:
    monkeypatch.setattr(
        ds,
        "current_runtime_commit",
        lambda: (sha or ""),
    )


def test_snapshot_exposes_required_fields(monkeypatch):
    _force_runtime_commit(monkeypatch, VALID_SHA_A)
    monkeypatch.setenv("REPLIT_DEPLOYMENT_ID", "dep_123")

    snap = ds.deployment_sync_snapshot(
        runtime_mode="NORMAL",
        policy_version="v7",
        registry_available=True,
    )

    for key in (
        "git_commit",
        "deployment_revision",
        "policy_version",
        "runtime_status",
        "expected_git_commit",
        "commit_match",
    ):
        assert key in snap, f"missing required field: {key}"

    assert snap["git_commit"] == VALID_SHA_A
    assert snap["deployment_revision"] == "dep_123"
    assert snap["policy_version"] == "v7"
    assert snap["runtime_status"] == "NORMAL"
    assert snap["expected_git_commit"] == ""
    assert snap["commit_match"] == ds.COMMIT_MATCH_UNENFORCED


def test_snapshot_runtime_status_reflects_registry_and_mode(monkeypatch):
    _force_runtime_commit(monkeypatch, VALID_SHA_A)

    assert (
        ds.deployment_sync_snapshot(
            runtime_mode="NORMAL", policy_version="v1", registry_available=False
        )["runtime_status"]
        == "FAIL_CLOSED"
    )
    assert (
        ds.deployment_sync_snapshot(
            runtime_mode="DEGRADED", policy_version="v1", registry_available=True
        )["runtime_status"]
        == "DEGRADED"
    )


def test_validate_unenforced_when_no_expected_env(monkeypatch):
    _force_runtime_commit(monkeypatch, VALID_SHA_A)
    result = ds.validate_deployment_commit_sync()
    assert result["commit_match"] == ds.COMMIT_MATCH_UNENFORCED


def test_validate_passes_when_runtime_matches_expected(monkeypatch):
    _force_runtime_commit(monkeypatch, VALID_SHA_A)
    monkeypatch.setenv("USBAY_EXPECTED_GIT_COMMIT", VALID_SHA_A.upper())

    audit_events = []

    def hook(action, event):
        audit_events.append((action, event))

    result = ds.validate_deployment_commit_sync(audit_hook=hook)
    assert result["commit_match"] == ds.COMMIT_MATCH_OK
    assert audit_events == []


def test_validate_fail_closed_on_mismatch_emits_audit_and_log(monkeypatch, caplog):
    _force_runtime_commit(monkeypatch, VALID_SHA_A)
    monkeypatch.setenv("GITHUB_MAIN_SHA", VALID_SHA_B)
    monkeypatch.setenv("REPLIT_DEPLOYMENT_ID", "dep_xyz")

    audit_events = []

    def hook(action, event):
        audit_events.append((action, event))

    caplog.set_level(logging.ERROR, logger="usbay.gateway.deployment_sync")

    with pytest.raises(ds.DeploymentCommitMismatchError) as excinfo:
        ds.validate_deployment_commit_sync(audit_hook=hook)

    assert excinfo.value.expected == VALID_SHA_B
    assert excinfo.value.actual == VALID_SHA_A
    assert VALID_SHA_A in str(excinfo.value)
    assert VALID_SHA_B in str(excinfo.value)

    assert len(audit_events) == 1
    action, event = audit_events[0]
    assert action == ds.MISMATCH_AUDIT_ACTION
    assert event["expected_git_commit"] == VALID_SHA_B
    assert event["actual_git_commit"] == VALID_SHA_A
    assert event["deployment_revision"] == "dep_xyz"

    assert any(
        "deployment_commit_mismatch" in r.getMessage() for r in caplog.records
    )


def test_validate_unresolved_runtime_commit_treated_as_mismatch(monkeypatch):
    _force_runtime_commit(monkeypatch, "")
    monkeypatch.setenv("USBAY_EXPECTED_GIT_COMMIT", VALID_SHA_A)
    with pytest.raises(ds.DeploymentCommitMismatchError):
        ds.validate_deployment_commit_sync()


def test_audit_hook_failure_does_not_mask_fail_closed(monkeypatch):
    _force_runtime_commit(monkeypatch, VALID_SHA_A)
    monkeypatch.setenv("USBAY_EXPECTED_GIT_COMMIT", VALID_SHA_B)

    def broken_hook(action, event):
        raise RuntimeError("audit backend down")

    with pytest.raises(ds.DeploymentCommitMismatchError):
        ds.validate_deployment_commit_sync(audit_hook=broken_hook)


def test_logs_and_error_contain_no_unexpected_env_values(monkeypatch, caplog):
    # Plant a sensitive-looking env var and verify it never appears
    # in the structured log record or the exception message.
    secret_marker = "SECRET_TOKEN_DO_NOT_LEAK_42"
    monkeypatch.setenv("USBAY_API_KEY", secret_marker)
    monkeypatch.setenv("USBAY_EXPECTED_GIT_COMMIT", VALID_SHA_B)
    _force_runtime_commit(monkeypatch, VALID_SHA_A)

    caplog.set_level(logging.DEBUG, logger="usbay.gateway.deployment_sync")

    with pytest.raises(ds.DeploymentCommitMismatchError) as excinfo:
        ds.validate_deployment_commit_sync(audit_hook=lambda *a, **k: None)

    assert secret_marker not in str(excinfo.value)
    for record in caplog.records:
        assert secret_marker not in record.getMessage()
        assert secret_marker not in str(getattr(record, "deployment_sync", ""))


def test_invalid_sha_in_env_is_treated_as_unset(monkeypatch):
    _force_runtime_commit(monkeypatch, VALID_SHA_A)
    monkeypatch.setenv("USBAY_EXPECTED_GIT_COMMIT", "not-a-real-sha")
    result = ds.validate_deployment_commit_sync()
    assert result["commit_match"] == ds.COMMIT_MATCH_UNENFORCED


# --------- /api/status integration ---------


def _build_test_client(monkeypatch):
    # Import lazily so monkeypatched env propagates if needed.
    from fastapi.testclient import TestClient
    from gateway import app as gateway_app

    return TestClient(gateway_app.app)


def test_api_status_exposes_sync_fields(monkeypatch):
    _force_runtime_commit(monkeypatch, VALID_SHA_A)
    monkeypatch.setenv("REPLIT_DEPLOYMENT_ID", "dep_status_test")

    client = _build_test_client(monkeypatch)
    res = client.get("/api/status")
    assert res.status_code in (200, 503)
    body = res.json()

    for key in ("git_commit", "deployment_revision", "policy_version", "runtime_status"):
        assert key in body, f"/api/status missing required field: {key}"

    assert body["git_commit"] == VALID_SHA_A
    assert body["deployment_revision"] == "dep_status_test"
    assert body["runtime_status"] in {"NORMAL", "DEGRADED", "FAIL_CLOSED"}
