from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from governance.security_gates import (
    BLOCKED,
    VERIFIED,
    evaluate_authentication_gate,
    evaluate_dependency_gate,
    evaluate_external_pentest_gate,
    evaluate_security_gate_chain,
    evaluate_zap_gate,
)


def _timestamp(hours_ago: int = 0) -> str:
    value = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return value.isoformat().replace("+00:00", "Z")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _common(schema: str) -> dict:
    return {
        "schema": schema,
        "generated_at": _timestamp(),
        "decision": VERIFIED,
        "fail_closed": False,
        "errors": [],
    }


def _write_zap(root: Path, **overrides) -> None:
    payload = {
        **_common("usbay.pbsec001.zap_security_gate.v1"),
        "scan_completed": True,
        "critical_findings": 0,
        "high_findings": 0,
        "report_hash": "zap-report-hash",
        "target_redacted": True,
        "raw_payload_logged": False,
    }
    payload.update(overrides)
    _write_json(root / "governance/evidence/pbsec001_zap/zap_security_gate.json", payload)


def _write_dependency(root: Path, **overrides) -> None:
    payload = {
        **_common("usbay.pbsec002.dependency_security_gate.v1"),
        "scan_completed": True,
        "sources": {"codeql": True, "dependabot": True, "pip_audit": True, "npm_audit": False},
        "critical_findings": 0,
        "high_findings": 0,
        "dependency_lockfile_present": True,
        "report_hash": "dependency-report-hash",
        "raw_payload_logged": False,
    }
    payload.update(overrides)
    _write_json(root / "governance/evidence/pbsec002_dependency_security/dependency_security_gate.json", payload)


def _write_auth(root: Path, **overrides) -> None:
    payload = {
        **_common("usbay.pbsec003.authentication_security_gate.v1"),
        "auth_bypass_detected": False,
        "replay_acceptance_detected": False,
        "nonce_required": True,
        "challenge_expiry_verified": True,
        "session_expiry_verified": True,
        "privileged_route_protected": True,
        "report_hash": "auth-report-hash",
    }
    payload.update(overrides)
    _write_json(root / "governance/evidence/pbsec003_authentication_security/authentication_security_gate.json", payload)


def _write_pentest(root: Path, **overrides) -> None:
    payload = {
        **_common("usbay.pbsec004.external_pentest_gate.v1"),
        "pentest_completed": True,
        "provider_or_reviewer": "external-reviewer",
        "remediation_completed": True,
        "unresolved_critical_findings": 0,
        "unresolved_high_findings": 0,
        "approval_signature_or_hash": "pentest-approval-hash",
        "approved_at": _timestamp(),
    }
    payload.update(overrides)
    _write_json(root / "governance/evidence/pbsec004_external_pentest/external_pentest_gate.json", payload)


def _write_release(root: Path, **overrides) -> None:
    payload = {
        **_common("usbay.pbsec005.production_release_gate.v1"),
        "human_approved": True,
        "approver_role": "authorized-human-reviewer",
        "approved_scope": "production-release",
        "approved_at": _timestamp(),
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
    }
    payload.update(overrides)
    _write_json(root / "governance/evidence/pbsec005_production_release/production_release_gate.json", payload)


def _write_all_verified(root: Path) -> None:
    _write_zap(root)
    _write_dependency(root)
    _write_auth(root)
    _write_pentest(root)
    _write_release(root)


def test_zap_gate_blocks_missing_report(tmp_path: Path) -> None:
    result = evaluate_zap_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PB-SEC-001_EVIDENCE_MISSING" in result.reason_codes


def test_zap_gate_blocks_critical_and_high_findings(tmp_path: Path) -> None:
    _write_zap(tmp_path, critical_findings=1, high_findings=1)

    result = evaluate_zap_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC001_CRITICAL_FINDINGS_PRESENT" in result.reason_codes
    assert "PBSEC001_HIGH_FINDINGS_PRESENT" in result.reason_codes


def test_clean_zap_evidence_verifies(tmp_path: Path) -> None:
    _write_zap(tmp_path)

    result = evaluate_zap_gate(tmp_path)

    assert result.decision == VERIFIED
    assert result.fail_closed is False


def test_zap_gate_blocks_raw_payload_logging(tmp_path: Path) -> None:
    _write_zap(tmp_path, raw_payload_logged=True)

    result = evaluate_zap_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC001_RAW_PAYLOAD_LOGGED" in result.reason_codes


def test_dependency_gate_blocks_missing_dependency_evidence(tmp_path: Path) -> None:
    _write_dependency(tmp_path, sources={"codeql": False, "dependabot": False, "pip_audit": False, "npm_audit": False})

    result = evaluate_dependency_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC002_DEPENDENCY_EVIDENCE_MISSING" in result.reason_codes


def test_dependency_gate_blocks_high_dependency_findings(tmp_path: Path) -> None:
    _write_dependency(tmp_path, high_findings=1)

    result = evaluate_dependency_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC002_HIGH_DEPENDENCY_FINDING" in result.reason_codes


def test_clean_dependency_evidence_verifies(tmp_path: Path) -> None:
    _write_dependency(tmp_path)

    result = evaluate_dependency_gate(tmp_path)

    assert result.decision == VERIFIED


def test_authentication_gate_blocks_missing_nonce_and_expiry(tmp_path: Path) -> None:
    _write_auth(tmp_path, nonce_required=False, challenge_expiry_verified=False)

    result = evaluate_authentication_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC003_NONCE_REQUIRED_MISSING" in result.reason_codes
    assert "PBSEC003_CHALLENGE_EXPIRY_MISSING" in result.reason_codes


def test_authentication_gate_blocks_replay_and_auth_bypass(tmp_path: Path) -> None:
    _write_auth(tmp_path, replay_acceptance_detected=True, auth_bypass_detected=True)

    result = evaluate_authentication_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC003_REPLAY_ACCEPTANCE_DETECTED" in result.reason_codes
    assert "PBSEC003_AUTH_BYPASS_DETECTED" in result.reason_codes


def test_valid_auth_controls_verify(tmp_path: Path) -> None:
    _write_auth(tmp_path)

    result = evaluate_authentication_gate(tmp_path)

    assert result.decision == VERIFIED


def test_external_pentest_gate_blocks_without_passed_pentest_and_remediation_approval(tmp_path: Path) -> None:
    _write_pentest(tmp_path, pentest_completed=False, remediation_completed=False)

    result = evaluate_external_pentest_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC004_PENTEST_NOT_COMPLETED" in result.reason_codes
    assert "PBSEC004_REMEDIATION_INCOMPLETE" in result.reason_codes


def test_external_pentest_gate_blocks_unresolved_findings(tmp_path: Path) -> None:
    _write_pentest(tmp_path, unresolved_high_findings=1)

    result = evaluate_external_pentest_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC004_UNRESOLVED_HIGH_FINDINGS" in result.reason_codes


def test_valid_external_pentest_evidence_verifies(tmp_path: Path) -> None:
    _write_pentest(tmp_path)

    result = evaluate_external_pentest_gate(tmp_path)

    assert result.decision == VERIFIED


def test_production_release_gate_blocks_without_human_approval(tmp_path: Path) -> None:
    _write_all_verified(tmp_path)
    _write_release(tmp_path, human_approved=False)

    result = evaluate_security_gate_chain(root=tmp_path, pb020_verified=True)

    assert result["status"] == BLOCKED
    assert result["production_release_approved"] is False
    assert "PBSEC005_HUMAN_APPROVAL_MISSING" in result["blockers"]


def test_production_release_gate_rejects_ai_codex_approval(tmp_path: Path) -> None:
    _write_all_verified(tmp_path)
    _write_release(tmp_path, approver_actor="codex", no_ai_auto_approval=False)

    result = evaluate_security_gate_chain(root=tmp_path, pb020_verified=True)

    assert result["status"] == BLOCKED
    assert "PBSEC005_AI_APPROVER_REJECTED" in result["blockers"]
    assert "PBSEC005_AI_AUTO_APPROVAL_NOT_REJECTED" in result["blockers"]


def test_security_gate_chain_verifies_when_all_gates_and_human_approval_pass(tmp_path: Path) -> None:
    _write_all_verified(tmp_path)

    result = evaluate_security_gate_chain(root=tmp_path, pb020_verified=True)

    assert result["status"] == "APPROVED"
    assert result["production_release_approved"] is True
    assert result["blockers"] == []


def test_security_gate_chain_blocks_when_pb020_is_not_verified(tmp_path: Path) -> None:
    _write_all_verified(tmp_path)

    result = evaluate_security_gate_chain(root=tmp_path, pb020_verified=False)

    assert result["status"] == BLOCKED
    assert "PBSEC005_PB020_NOT_VERIFIED" in result["blockers"]
