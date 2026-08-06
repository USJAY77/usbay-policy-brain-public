"""Drift-truth tests for the dashboard telemetry chips.

The Sync chip must derive from the authoritative deployment-sync
comparison (expected release SHA vs runtime commit), and the Verifier
chip may claim DRIFT only for an actual continuity failure — an
unconfigured verifier set is truthful NOT ENROLLED. A real mismatch
must surface immediately (values are computed per request, no cache).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import gateway.app as ga
from governance import deployment_sync

REPO = Path(__file__).resolve().parents[1]
HEAD = subprocess.run(
    ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True
).stdout.strip()

_ENV_VARS = (
    "USBAY_EXPECTED_GIT_COMMIT",
    "GITHUB_MAIN_SHA",
    "USBAY_VERIFIER_CONTINUITY_NODES_JSON",
    "USBAY_VERIFIER_PUBLIC_KEYS_JSON",
    "USBAY_DEVICE_IDENTITY_PACKET_JSON",
    "USBAY_DEVICE_IDENTITY_PUBLIC_KEY_PEM",
    "USBAY_DEVICE_TRUST_RENEWAL_PACKET_JSON",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Isolate every render from ambient expected-commit / trust env."""
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _render(monkeypatch, expected: str | None) -> str:
    if expected is not None:
        monkeypatch.setenv("USBAY_EXPECTED_GIT_COMMIT", expected)
    resp = ga.dashboard()
    return resp.body.decode("utf-8") if hasattr(resp, "body") else str(resp)


def _runtime_commit() -> str:
    """The commit the runtime actually reports (authoritative actual)."""
    return deployment_sync.current_runtime_commit()


def test_all_shas_match_shows_synced(monkeypatch):
    actual = _runtime_commit()
    assert actual, "runtime commit must resolve in the workspace"
    html = _render(monkeypatch, actual)
    assert "Sync <b>SYNCED</b>" in html
    assert "Sync <b>DRIFT</b>" not in html


def test_commit_mismatch_shows_drift_immediately(monkeypatch):
    html = _render(monkeypatch, "0" * 40)
    assert "Sync <b>DRIFT</b>" in html
    assert "Sync <b>SYNCED</b>" not in html


def test_unenforced_is_labelled_truthfully_not_synced(monkeypatch):
    html = _render(monkeypatch, None)
    assert "Sync <b>UNENFORCED</b>" in html
    assert "Sync <b>SYNCED</b>" not in html
    assert "Sync <b>DRIFT</b>" not in html


def test_unknown_runtime_commit_shows_unknown(monkeypatch):
    monkeypatch.setenv("USBAY_EXPECTED_GIT_COMMIT", _runtime_commit() or "0" * 40)
    monkeypatch.setattr(ga, "deployment_sync_snapshot", lambda **kw: {
        "git_commit": "",
        "deployment_revision": "test",
        "policy_version": "",
        "runtime_status": "NORMAL",
        "expected_git_commit": "0" * 40,
        "commit_match": "unknown",
    })
    html = ga.dashboard().body.decode("utf-8")
    assert "Sync <b>UNKNOWN</b>" in html
    assert "Sync <b>SYNCED</b>" not in html


def test_blocked_takes_precedence_over_synced(monkeypatch):
    # Simulate fail-closed runtime: state_label BLOCKED must win even
    # when the commit comparison would read SYNCED.
    real_snapshot = ga.runtime_status_snapshot

    def blocked_snapshot():
        snap = real_snapshot()
        snap["status"] = "FAIL_CLOSED"
        snap["mode"] = "FAIL_CLOSED"
        return snap

    monkeypatch.setenv("USBAY_EXPECTED_GIT_COMMIT", _runtime_commit() or "0" * 40)
    monkeypatch.setattr(ga, "runtime_status_snapshot", blocked_snapshot)
    html = ga.dashboard().body.decode("utf-8")
    assert "Sync <b>SYNCED</b>" not in html


def test_stale_drift_clears_after_refresh(monkeypatch):
    # drift render first, then a corrected render must clear it (no cache)
    html_bad = _render(monkeypatch, "0" * 40)
    assert "Sync <b>DRIFT</b>" in html_bad
    monkeypatch.setenv("USBAY_EXPECTED_GIT_COMMIT", _runtime_commit())
    html_ok = ga.dashboard().body.decode("utf-8")
    assert "Sync <b>SYNCED</b>" in html_ok
    assert "Sync <b>DRIFT</b>" not in html_ok


def test_unconfigured_verifier_is_not_enrolled_not_drift(monkeypatch):
    html = _render(monkeypatch, _runtime_commit())
    assert "Verifier <b>NOT ENROLLED</b>" in html
    assert "Verifier <b>DRIFT</b>" not in html


def test_failed_verifier_shows_drift(monkeypatch):
    # malformed nodes JSON parses to a FAILED continuity node
    monkeypatch.setenv("USBAY_VERIFIER_CONTINUITY_NODES_JSON", "{not-json")
    html = _render(monkeypatch, _runtime_commit())
    assert "Verifier <b>DRIFT</b>" in html
    assert "Verifier <b>NOT ENROLLED</b>" not in html


def test_pilot_posture_stays_degraded_while_controls_unmet(monkeypatch):
    # device attestation intentionally unavailable in this environment —
    # the pilot chip must NOT be forced green
    html = _render(monkeypatch, _runtime_commit())
    assert "Pilot · <b>VERIFIED</b>" not in html
    assert "Pilot · <b>DEGRADED</b>" in html
