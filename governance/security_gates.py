from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EVIDENCE_ROOT = Path("governance/evidence")
DEFAULT_MAX_AGE_HOURS = 168.0
VERIFIED = "VERIFIED"
BLOCKED = "BLOCKED"
PENTEST_REQUIRED = "PENTEST_REQUIRED"
PENTEST_PASSED = "PENTEST_PASSED"
PENTEST_FAILED = "PENTEST_FAILED"

GATE_FILES = {
    "PB-SEC-001": Path("pbsec001_zap/zap_security_gate.json"),
    "PB-SEC-002": Path("pbsec002_dependency_security/dependency_security_gate.json"),
    "PB-SEC-003": Path("pbsec003_authentication_security/authentication_security_gate.json"),
    "PB-SEC-004": Path("pbsec004_external_pentest/external_pentest_gate.json"),
    "PB-SEC-005": Path("pbsec005_production_release/production_release_gate.json"),
}

GATE_SCHEMAS = {
    "PB-SEC-001": "usbay.pbsec001.zap_security_gate.v1",
    "PB-SEC-002": "usbay.pbsec002.dependency_security_gate.v1",
    "PB-SEC-003": "usbay.pbsec003.authentication_security_gate.v1",
    "PB-SEC-004": "usbay.pbsec004.external_pentest_gate.v1",
    "PB-SEC-005": "usbay.pbsec005.production_release_gate.v1",
}


@dataclass(frozen=True)
class SecurityGateResult:
    gate_id: str
    decision: str
    reason: str
    evidence_hash: str
    generated_at: str
    fail_closed: bool
    reason_codes: tuple[str, ...]

    @property
    def verified(self) -> bool:
        return self.decision == VERIFIED and not self.fail_closed

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "decision": self.decision,
            "reason": self.reason,
            "evidence_hash": self.evidence_hash,
            "generated_at": self.generated_at,
            "fail_closed": self.fail_closed,
            "reason_codes": list(self.reason_codes),
        }


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _blocked(gate_id: str, reason: str, *, reason_codes: list[str] | None = None) -> SecurityGateResult:
    return SecurityGateResult(
        gate_id=gate_id,
        decision=BLOCKED,
        reason=reason,
        evidence_hash="",
        generated_at="",
        fail_closed=True,
        reason_codes=tuple(reason_codes or [reason]),
    )


def _load_gate_payload(root: Path, gate_id: str) -> tuple[dict[str, Any] | None, SecurityGateResult | None]:
    path = root / EVIDENCE_ROOT / GATE_FILES[gate_id]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, _blocked(gate_id, f"{gate_id}_EVIDENCE_MISSING")
    except json.JSONDecodeError:
        return None, _blocked(gate_id, f"{gate_id}_EVIDENCE_MALFORMED")
    except OSError:
        return None, _blocked(gate_id, f"{gate_id}_EVIDENCE_UNREADABLE")
    if not isinstance(payload, dict):
        return None, _blocked(gate_id, f"{gate_id}_EVIDENCE_OBJECT_REQUIRED")
    return payload, None


def _common_errors(gate_id: str, payload: dict[str, Any], *, max_age_hours: float, now: datetime) -> list[str]:
    errors: list[str] = []
    if payload.get("schema") != GATE_SCHEMAS[gate_id]:
        errors.append(f"{gate_id}_SCHEMA_INVALID")
    generated_at = _parse_timestamp(payload.get("generated_at"))
    if generated_at is None:
        errors.append(f"{gate_id}_TIMESTAMP_INVALID")
    else:
        age_hours = (now - generated_at).total_seconds() / 3600
        if age_hours < 0 or age_hours > max_age_hours:
            errors.append(f"{gate_id}_EVIDENCE_STALE")
    if payload.get("decision") not in {VERIFIED, BLOCKED}:
        errors.append(f"{gate_id}_DECISION_INVALID")
    raw_errors = payload.get("errors", [])
    if raw_errors and not isinstance(raw_errors, list):
        errors.append(f"{gate_id}_ERRORS_INVALID")
    if isinstance(raw_errors, list):
        errors.extend(str(error) for error in raw_errors if error)
    return errors


def _finalize(gate_id: str, payload: dict[str, Any], errors: list[str]) -> SecurityGateResult:
    decision = VERIFIED if not errors and payload.get("decision") == VERIFIED and payload.get("fail_closed") is False else BLOCKED
    reason_codes = sorted(dict.fromkeys(errors or [f"{gate_id}_VERIFIED"]))
    return SecurityGateResult(
        gate_id=gate_id,
        decision=decision,
        reason=reason_codes[0],
        evidence_hash=sha256_text(canonical_json(payload)),
        generated_at=str(payload.get("generated_at", "")),
        fail_closed=decision != VERIFIED,
        reason_codes=tuple(reason_codes),
    )


def evaluate_zap_gate(root: Path, *, max_age_hours: float = DEFAULT_MAX_AGE_HOURS, now: datetime | None = None) -> SecurityGateResult:
    gate_id = "PB-SEC-001"
    payload, blocked = _load_gate_payload(root, gate_id)
    if blocked:
        return blocked
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    errors = _common_errors(gate_id, payload, max_age_hours=max_age_hours, now=effective_now)
    if payload.get("scan_report_present") is not True:
        errors.append("PBSEC001_SCAN_REPORT_MISSING")
    if payload.get("scan_report_malformed") is True:
        errors.append("PBSEC001_SCAN_REPORT_MALFORMED")
    if int(payload.get("critical_findings", 0) or 0) > 0:
        errors.append("PBSEC001_CRITICAL_FINDINGS_PRESENT")
    if int(payload.get("high_findings", 0) or 0) > 0:
        errors.append("PBSEC001_HIGH_FINDINGS_PRESENT")
    return _finalize(gate_id, payload, errors)


def evaluate_dependency_gate(root: Path, *, max_age_hours: float = DEFAULT_MAX_AGE_HOURS, now: datetime | None = None) -> SecurityGateResult:
    gate_id = "PB-SEC-002"
    payload, blocked = _load_gate_payload(root, gate_id)
    if blocked:
        return blocked
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    errors = _common_errors(gate_id, payload, max_age_hours=max_age_hours, now=effective_now)
    sources = payload.get("sources", {})
    if not isinstance(sources, dict) or not any(bool(value) for value in sources.values()):
        errors.append("PBSEC002_DEPENDENCY_EVIDENCE_MISSING")
    if int(payload.get("critical_findings", 0) or 0) > 0:
        errors.append("PBSEC002_CRITICAL_DEPENDENCY_FINDING")
    if int(payload.get("high_findings", 0) or 0) > 0:
        errors.append("PBSEC002_HIGH_DEPENDENCY_FINDING")
    return _finalize(gate_id, payload, errors)


def evaluate_authentication_gate(root: Path, *, max_age_hours: float = DEFAULT_MAX_AGE_HOURS, now: datetime | None = None) -> SecurityGateResult:
    gate_id = "PB-SEC-003"
    payload, blocked = _load_gate_payload(root, gate_id)
    if blocked:
        return blocked
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    errors = _common_errors(gate_id, payload, max_age_hours=max_age_hours, now=effective_now)
    required_true = {
        "replay_protection_verified": "PBSEC003_REPLAY_PROTECTION_MISSING",
        "nonce_enforcement_verified": "PBSEC003_NONCE_ENFORCEMENT_MISSING",
        "challenge_expiry_verified": "PBSEC003_CHALLENGE_EXPIRY_MISSING",
        "session_validation_verified": "PBSEC003_SESSION_VALIDATION_MISSING",
        "auth_bypass_prevention_verified": "PBSEC003_AUTH_BYPASS_PREVENTION_MISSING",
    }
    for field, code in required_true.items():
        if payload.get(field) is not True:
            errors.append(code)
    if payload.get("replay_accepted") is True:
        errors.append("PBSEC003_REPLAY_ACCEPTED")
    if payload.get("auth_bypass_detected") is True:
        errors.append("PBSEC003_AUTH_BYPASS_DETECTED")
    return _finalize(gate_id, payload, errors)


def evaluate_external_pentest_gate(root: Path, *, max_age_hours: float = DEFAULT_MAX_AGE_HOURS, now: datetime | None = None) -> SecurityGateResult:
    gate_id = "PB-SEC-004"
    payload, blocked = _load_gate_payload(root, gate_id)
    if blocked:
        return blocked
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    errors = _common_errors(gate_id, payload, max_age_hours=max_age_hours, now=effective_now)
    if payload.get("pentest_state") != PENTEST_PASSED:
        errors.append("PBSEC004_PENTEST_NOT_PASSED")
    if payload.get("external_pentest_approval_present") is not True:
        errors.append("PBSEC004_EXTERNAL_PENTEST_APPROVAL_MISSING")
    if payload.get("remediation_approval_present") is not True:
        errors.append("PBSEC004_REMEDIATION_APPROVAL_MISSING")
    return _finalize(gate_id, payload, errors)


def evaluate_production_release_gate(
    root: Path,
    prerequisites: dict[str, SecurityGateResult],
    pb020_verified: bool,
    *,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
    now: datetime | None = None,
) -> SecurityGateResult:
    gate_id = "PB-SEC-005"
    payload, blocked = _load_gate_payload(root, gate_id)
    if blocked:
        return blocked
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    errors = _common_errors(gate_id, payload, max_age_hours=max_age_hours, now=effective_now)
    if not pb020_verified:
        errors.append("PBSEC005_PB020_NOT_VERIFIED")
    for prerequisite in ("PB-SEC-001", "PB-SEC-002", "PB-SEC-003", "PB-SEC-004"):
        if prerequisite not in prerequisites or not prerequisites[prerequisite].verified:
            errors.append(f"PBSEC005_PREREQUISITE_BLOCKED:{prerequisite}")
    if payload.get("human_approval_present") is not True:
        errors.append("PBSEC005_HUMAN_APPROVAL_MISSING")
    if payload.get("production_release_approved") is not True:
        errors.append("PBSEC005_PRODUCTION_APPROVAL_MISSING")
    return _finalize(gate_id, payload, errors)


def evaluate_security_gate_chain(
    *,
    root: Path,
    pb020_verified: bool,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
    now: datetime | None = None,
) -> dict[str, Any]:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    gates = {
        "PB-SEC-001": evaluate_zap_gate(root, max_age_hours=max_age_hours, now=effective_now),
        "PB-SEC-002": evaluate_dependency_gate(root, max_age_hours=max_age_hours, now=effective_now),
        "PB-SEC-003": evaluate_authentication_gate(root, max_age_hours=max_age_hours, now=effective_now),
        "PB-SEC-004": evaluate_external_pentest_gate(root, max_age_hours=max_age_hours, now=effective_now),
    }
    gates["PB-SEC-005"] = evaluate_production_release_gate(
        root,
        prerequisites=gates,
        pb020_verified=pb020_verified,
        max_age_hours=max_age_hours,
        now=effective_now,
    )
    blockers = [
        code
        for gate in gates.values()
        if not gate.verified
        for code in gate.reason_codes
    ]
    approved = gates["PB-SEC-005"].verified and not blockers
    return {
        "schema_version": "usbay.pbsec.security_gate_chain.v1",
        "status": "APPROVED" if approved else BLOCKED,
        "production_release_approved": approved,
        "fail_closed": not approved,
        "gates": {gate_id: result.to_dict() for gate_id, result in gates.items()},
        "blockers": sorted(dict.fromkeys(blockers)),
        "security_evidence_hash": sha256_text(canonical_json({gate_id: result.to_dict() for gate_id, result in gates.items()})),
    }
