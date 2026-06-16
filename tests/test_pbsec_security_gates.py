from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from governance.security_gates import (
    BLOCKED,
    PENTEST_PASSED,
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
        "scan_report_present": True,
        "scan_report_malformed": False,
        "critical_findings": 0,
        "high_findings": 0,
    }
    payload.update(overrides)
    _write_json(root / "governance/evidence/pbsec001_zap/zap_security_gate.json", payload)


def _write_dependency(root: Path, **overrides) -> None:
    payload = {
        **_common("usbay.pbsec002.dependency_security_gate.v1"),
        "sources": {"codeql": True, "dependabot": True, "pip_audit": True, "npm_audit": False},
        "critical_findings": 0,
        "high_findings": 0,
    }
    payload.update(overrides)
    _write_json(root / "governance/evidence/pbsec002_dependency_security/dependency_security_gate.json", payload)


def _write_auth(root: Path, **overrides) -> None:
    payload = {
        **_common("usbay.pbsec003.authentication_security_gate.v1"),
        "replay_protection_verified": True,
        "nonce_enforcement_verified": True,
        "challenge_expiry_verified": True,
        "session_validation_verified": True,
        "auth_bypass_prevention_verified": True,
        "replay_accepted": False,
        "auth_bypass_detected": False,
    }
    payload.update(overrides)
    _write_json(root / "governance/evidence/pbsec003_authentication_security/authentication_security_gate.json", payload)


def _write_pentest(root: Path, **overrides) -> None:
    payload = {
        **_common("usbay.pbsec004.external_pentest_gate.v1"),
        "pentest_state": PENTEST_PASSED,
        "external_pentest_approval_present": True,
        "remediation_approval_present": True,
    }
    payload.update(overrides)
    _write_json(root / "governance/evidence/pbsec004_external_pentest/external_pentest_gate.json", payload)


def _write_release(root: Path, **overrides) -> None:
    payload = {
        **_common("usbay.pbsec005.production_release_gate.v1"),
        "human_approval_present": True,
        "production_release_approved": True,
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


def test_zap_gate_blocks_malformed_report_flag(tmp_path: Path) -> None:
    _write_zap(tmp_path, scan_report_malformed=True)

    result = evaluate_zap_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC001_SCAN_REPORT_MALFORMED" in result.reason_codes


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


def test_authentication_gate_blocks_missing_nonce_and_expiry(tmp_path: Path) -> None:
    _write_auth(tmp_path, nonce_enforcement_verified=False, challenge_expiry_verified=False)

    result = evaluate_authentication_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC003_NONCE_ENFORCEMENT_MISSING" in result.reason_codes
    assert "PBSEC003_CHALLENGE_EXPIRY_MISSING" in result.reason_codes


def test_authentication_gate_blocks_replay_and_auth_bypass(tmp_path: Path) -> None:
    _write_auth(tmp_path, replay_accepted=True, auth_bypass_detected=True)

    result = evaluate_authentication_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC003_REPLAY_ACCEPTED" in result.reason_codes
    assert "PBSEC003_AUTH_BYPASS_DETECTED" in result.reason_codes


def test_external_pentest_gate_blocks_without_passed_pentest_and_remediation_approval(tmp_path: Path) -> None:
    _write_pentest(tmp_path, pentest_state="PENTEST_FAILED", remediation_approval_present=False)

    result = evaluate_external_pentest_gate(tmp_path)

    assert result.decision == BLOCKED
    assert "PBSEC004_PENTEST_NOT_PASSED" in result.reason_codes
    assert "PBSEC004_REMEDIATION_APPROVAL_MISSING" in result.reason_codes


def test_production_release_gate_blocks_without_human_approval(tmp_path: Path) -> None:
    _write_all_verified(tmp_path)
    _write_release(tmp_path, human_approval_present=False, production_release_approved=False)

    result = evaluate_security_gate_chain(root=tmp_path, pb020_verified=True)

    assert result["status"] == BLOCKED
    assert result["production_release_approved"] is False
    assert "PBSEC005_HUMAN_APPROVAL_MISSING" in result["blockers"]


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
