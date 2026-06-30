from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from governance.runtime_governance_state import (
    PROMOTE_BLOCKED,
    PROMOTE_READY,
    READY,
    SCORECARD,
    evaluate_runtime_governance_state,
)


PBSEC_GATE_FILES = {
    "PB-SEC-001": ("pbsec001_zap/zap_security_gate.json", "usbay.pbsec001.zap_security_gate.v1"),
    "PB-SEC-002": ("pbsec002_dependency_security/dependency_security_gate.json", "usbay.pbsec002.dependency_security_gate.v1"),
    "PB-SEC-003": ("pbsec003_authentication_security/authentication_security_gate.json", "usbay.pbsec003.authentication_security_gate.v1"),
    "PB-SEC-004": ("pbsec004_external_pentest/external_pentest_gate.json", "usbay.pbsec004.external_pentest_gate.v1"),
    "PB-SEC-005": ("pbsec005_production_release/production_release_gate.json", "usbay.pbsec005.production_release_gate.v1"),
}


def _timestamp(hours_ago: int = 0) -> str:
    value = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return value.isoformat().replace("+00:00", "Z")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_pb020(root: Path, *, generated_at: str | None = None, pb018_decision: str = "VERIFIED") -> None:
    generated_at = generated_at or _timestamp()
    common = {
        "generated_at": generated_at,
        "decision": "VERIFIED",
        "fail_closed": False,
        "errors": [],
    }
    evidence = root / "governance" / "evidence"
    _write_json(
        evidence / "pb020_freshness_report.json",
        {
            "schema": "usbay.pb020.freshness_report.v1",
            **common,
            "fresh_artifacts": 12,
            "total_artifacts": 12,
        },
    )
    _write_json(
        evidence / "pb020_staleness_report.json",
        {
            "schema": "usbay.pb020.staleness_report.v1",
            **common,
            "stale_artifacts": [],
            "stale_artifact_count": 0,
            "pb019_requirement": "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN",
        },
    )
    _write_json(
        evidence / "pb020_version_alignment_report.json",
        {
            "schema": "usbay.pb020.version_alignment_report.v1",
            **common,
            "version_mismatches": 0,
            "governance_version_mismatch_detected": False,
        },
    )
    _write_json(
        evidence / SCORECARD,
        {
            "schema": "usbay.pb020.evidence_freshness_scorecard.v1",
            **common,
            "freshness_score": 100.0,
            "version_alignment_score": 100.0,
            "pb016_decision": "VERIFIED",
            "pb017_decision": "VERIFIED",
            "pb018_decision": pb018_decision,
            "pb019_requirement": "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN",
            "stale_artifacts": 0,
            "version_mismatches": 0,
            "certification_result_trusted": pb018_decision == "VERIFIED",
            "maturity_report_trusted": True,
            "action_tracker_trusted": True,
        },
    )


def _write_pbsec_approved(root: Path) -> None:
    generated_at = _timestamp()
    evidence = root / "governance" / "evidence"
    common = {
        "generated_at": generated_at,
        "decision": "VERIFIED",
        "fail_closed": False,
        "errors": [],
    }
    for _gate_id, (relative, schema) in PBSEC_GATE_FILES.items():
        payload = {"schema": schema, **common}
        if relative.startswith("pbsec001"):
            payload.update({
                "scan_completed": True,
                "critical_findings": 0,
                "high_findings": 0,
                "report_hash": "zap-report-hash",
                "target_redacted": True,
                "raw_payload_logged": False,
            })
        elif relative.startswith("pbsec002"):
            payload.update({
                "scan_completed": True,
                "sources": {"codeql": True, "dependabot": True, "pip_audit": True, "npm_audit": False},
                "critical_findings": 0,
                "high_findings": 0,
                "dependency_lockfile_present": True,
                "report_hash": "dependency-report-hash",
                "raw_payload_logged": False,
            })
        elif relative.startswith("pbsec003"):
            payload.update({
                "auth_bypass_detected": False,
                "replay_acceptance_detected": False,
                "nonce_required": True,
                "challenge_expiry_verified": True,
                "session_expiry_verified": True,
                "privileged_route_protected": True,
                "report_hash": "auth-report-hash",
            })
        elif relative.startswith("pbsec004"):
            payload.update({
                "pentest_completed": True,
                "provider_or_reviewer": "external-reviewer",
                "remediation_completed": True,
                "unresolved_critical_findings": 0,
                "unresolved_high_findings": 0,
                "approval_signature_or_hash": "pentest-approval-hash",
                "approved_at": generated_at,
            })
        elif relative.startswith("pbsec005"):
            payload.update({
                "human_approved": True,
                "approver_role": "authorized-human-reviewer",
                "approved_scope": "production-release",
                "approved_at": generated_at,
                "approval_signature_or_hash": "release-approval-hash",
                "approver_actor": "human-reviewer",
                "evidence_hash_linkage": {
                    "PB-020": "pb020-hash",
                    "PB-SEC-001": "zap-report-hash",
                    "PB-SEC-002": "dependency-report-hash",
                    "PB-SEC-003": "auth-report-hash",
                    "PB-SEC-004": "pentest-approval-hash",
                },
                "no_ai_auto_approval": True,
            })
        _write_json(evidence / relative, payload)


def test_pb020_verified_evidence_sets_runtime_ready(tmp_path: Path) -> None:
    _write_pb020(tmp_path)
    _write_pbsec_approved(tmp_path)

    state = evaluate_runtime_governance_state(root=tmp_path)

    assert state.status == READY
    assert state.promote_state == PROMOTE_READY
    assert state.pb020_decision == "VERIFIED"
    assert state.fail_closed is False
    assert state.production_release_approved is True


def test_pb020_verified_without_pbsec005_blocks_production_runtime(tmp_path: Path) -> None:
    _write_pb020(tmp_path)

    state = evaluate_runtime_governance_state(root=tmp_path)

    assert state.status == "BLOCKED"
    assert state.promote_state == PROMOTE_BLOCKED
    assert state.production_release_approved is False
    assert "PBSEC005_PRODUCTION_RELEASE_NOT_APPROVED" in state.reason_codes


def test_pb020_missing_evidence_blocks_runtime(tmp_path: Path) -> None:
    state = evaluate_runtime_governance_state(root=tmp_path)

    assert state.status == "BLOCKED"
    assert state.promote_state == PROMOTE_BLOCKED
    assert state.fail_closed is True
    assert "PB020_EVIDENCE_DIR_MISSING" in state.reason_codes


def test_pb020_stale_evidence_blocks_runtime(tmp_path: Path) -> None:
    _write_pb020(tmp_path, generated_at=_timestamp(hours_ago=200))

    state = evaluate_runtime_governance_state(root=tmp_path, max_age_hours=24)

    assert state.status == "BLOCKED"
    assert state.promote_state == PROMOTE_BLOCKED
    assert "PB020_RUNTIME_EVIDENCE_STALE" in state.reason_codes


def test_pb018_not_verified_blocks_runtime(tmp_path: Path) -> None:
    _write_pb020(tmp_path, pb018_decision="BLOCKED")

    state = evaluate_runtime_governance_state(root=tmp_path)

    assert state.status == "BLOCKED"
    assert state.promote_state == PROMOTE_BLOCKED
    assert "PB018_DECISION_NOT_VERIFIED" in state.reason_codes


def test_promote_state_recalculates_after_evidence_changes(tmp_path: Path) -> None:
    _write_pb020(tmp_path, pb018_decision="BLOCKED")
    _write_pbsec_approved(tmp_path)
    blocked = evaluate_runtime_governance_state(root=tmp_path)

    _write_pb020(tmp_path, pb018_decision="VERIFIED")
    ready = evaluate_runtime_governance_state(root=tmp_path)

    assert blocked.promote_state == PROMOTE_BLOCKED
    assert ready.promote_state == PROMOTE_READY
    assert blocked.evidence_hash != ready.evidence_hash
