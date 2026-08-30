from __future__ import annotations

import json
from pathlib import Path

import pytest

from dashboard.governance_dashboard import (
    DashboardValidationError,
    build_dashboard_state,
    canonical_json,
    load_json_strict,
    render_dashboard,
    sanitize_evidence,
    validate_commit_lineage,
    write_outputs,
)


TIMESTAMP = "2026-05-22T00:00:00Z"


def _commit(sha: str, parent: str | None = None, verified: bool = True) -> dict:
    parents = [{"sha": parent}] if parent else []
    return {
        "sha": sha,
        "author": {"name": "USJAY77", "date": "2026-05-22T00:00:00Z"},
        "parents": parents,
        "verification": {
            "verified": verified,
            "reason": "valid" if verified else "unsigned",
            "signature": "-----BEGIN PGP " + "SIGNATURE-----\nunsafe\n-----END PGP " + "SIGNATURE-----",
            "payload": "raw governance " + "payload must not render",
            "verified_at": "2026-05-22T00:00:01Z",
        },
    }


def _write_fixture(root: Path) -> None:
    sha1 = "a" * 40
    sha2 = "b" * 40
    (root / "artifacts").mkdir(parents=True)
    (root / "pr41_timeline.json").write_text(json.dumps([_commit(sha1), _commit(sha2, sha1)]), encoding="utf-8")
    (root / "pr42_timeline.json").write_text(json.dumps([_commit(sha1), _commit(sha2, sha1)]), encoding="utf-8")
    reviews = [
        {"user": {"login": "USBAY-GLOBAL23"}, "state": "APPROVED", "submitted_at": "2026-05-22T00:02:00Z"},
        {"user": {"login": "USBAY-GOV-REVIEW"}, "state": "APPROVED", "submitted_at": "2026-05-22T00:03:00Z"},
    ]
    (root / "pr41_reviews.json").write_text(json.dumps(reviews), encoding="utf-8")
    (root / "pr42_reviews.json").write_text(json.dumps(reviews), encoding="utf-8")
    (root / "pr41_reviewers.json").write_text(json.dumps({"users": [], "teams": []}), encoding="utf-8")
    (root / "pr42_reviewers.json").write_text(json.dumps({"users": [{"login": "USBAY-GLOBAL23"}], "teams": []}), encoding="utf-8")
    (root / "artifacts" / "frontend-secret-exposure-audit.json").write_text(
        json.dumps(
            {
                "schema": "usbay.frontend_secret_exposure_audit.v1",
                "decision": "ALLOW",
                "finding_count": 0,
                "findings": [],
                "created_at_utc": TIMESTAMP,
                "audit_hash": "c" * 64,
                "scanner_policy_hash": "d" * 64,
            }
        ),
        encoding="utf-8",
    )


def test_dashboard_rendering_is_deterministic_and_sanitized(tmp_path: Path) -> None:
    _write_fixture(tmp_path)

    first = build_dashboard_state(root=tmp_path, timestamp=TIMESTAMP)
    second = build_dashboard_state(root=tmp_path, timestamp=TIMESTAMP)
    html = render_dashboard(first)

    assert canonical_json(first) == canonical_json(second)
    assert first["decision"] == "BLOCKED"
    assert "BRANCH_HYGIENE_EVIDENCE_MISSING" in first["governance_anomalies"]
    assert "USBAY Governance Evidence Dashboard" in html
    assert "-----BEGIN PGP " + "SIGNATURE-----" not in html
    assert "raw governance " + "payload" not in html


def test_provenance_timeline_detects_chain_break_and_unsigned_commit() -> None:
    sha1 = "a" * 40
    sha2 = "b" * 40
    anomalies = validate_commit_lineage([_commit(sha1), _commit(sha2, "c" * 40, verified=False)])

    assert f"UNSIGNED_GOVERNANCE_COMMIT:{sha2}" in anomalies
    assert f"PROVENANCE_CHAIN_BREAK:{sha2}" in anomalies


def test_audit_export_contains_required_decision_fields(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    state = build_dashboard_state(root=tmp_path, timestamp=TIMESTAMP, actor="codex", device="test-device")
    html_output = tmp_path / "artifacts" / "governance-dashboard.html"
    audit_output = tmp_path / "artifacts" / "governance-dashboard-audit.json"

    write_outputs(state, html_output, audit_output)
    exported = json.loads(audit_output.read_text(encoding="utf-8"))

    assert html_output.is_file()
    for field in ("actor", "device", "decision", "timestamp", "policy_version"):
        assert exported[field]
    assert exported["actor"] == "codex"
    assert exported["device"] == "test-device"
    assert exported["dashboard_audit_hash"]


def test_sanitizer_regression_redacts_secret_material() -> None:
    payload = {
        "token": "ghp" + "_aaaaaaaaaaaaaaaaaaaa",
        "nested": {"private_key": "-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END " + "PRIVATE KEY-----"},
        "safe": "visible",
    }

    sanitized = sanitize_evidence(payload)
    rendered = canonical_json(sanitized)

    assert sanitized["token"] == "[REDACTED]"
    assert sanitized["nested"]["private_key"] == "[REDACTED]"
    assert "PRIVATE KEY" not in rendered
    assert "ghp" + "_" not in rendered
    assert "visible" in rendered


def test_malformed_audit_artifact_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(DashboardValidationError, match="GOVERNANCE_DASHBOARD_EVIDENCE_MALFORMED"):
        load_json_strict(path)
