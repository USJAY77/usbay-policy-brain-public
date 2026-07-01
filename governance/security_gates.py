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


def _require_bool(
    errors: list[str],
    payload: dict[str, Any],
    field: str,
    expected: bool,
    code: str,
) -> None:
    if payload.get(field) is not expected:
        errors.append(code)


def _require_non_empty_string(errors: list[str], payload: dict[str, Any], field: str, code: str) -> None:
    if not isinstance(payload.get(field), str) or not payload.get(field, "").strip():
        errors.append(code)


def _require_non_negative_int(errors: list[str], payload: dict[str, Any], field: str, code: str) -> None:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        errors.append(code)


def _int_value(payload: dict[str, Any], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def _require_timestamp(
    errors: list[str],
    payload: dict[str, Any],
    field: str,
    code: str,
    *,
    stale_code: str,
    max_age_hours: float,
    now: datetime,
) -> None:
    parsed = _parse_timestamp(payload.get(field))
    if parsed is None:
        errors.append(code)
        return
    age_hours = (now - parsed).total_seconds() / 3600
    if age_hours < 0 or age_hours > max_age_hours:
        errors.append(stale_code)


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
    _require_bool(errors, payload, "scan_completed", True, "PBSEC001_SCAN_NOT_COMPLETED")
    _require_bool(errors, payload, "target_redacted", True, "PBSEC001_TARGET_NOT_REDACTED")
    _require_bool(errors, payload, "raw_payload_logged", False, "PBSEC001_RAW_PAYLOAD_LOGGED")
    _require_non_empty_string(errors, payload, "report_hash", "PBSEC001_REPORT_HASH_MISSING")
    _require_non_negative_int(errors, payload, "critical_findings", "PBSEC001_CRITICAL_FINDINGS_INVALID")
    _require_non_negative_int(errors, payload, "high_findings", "PBSEC001_HIGH_FINDINGS_INVALID")
    if _int_value(payload, "critical_findings") > 0:
        errors.append("PBSEC001_CRITICAL_FINDINGS_PRESENT")
    if _int_value(payload, "high_findings") > 0:
        errors.append("PBSEC001_HIGH_FINDINGS_PRESENT")
    return _finalize(gate_id, payload, errors)


def evaluate_dependency_gate(root: Path, *, max_age_hours: float = DEFAULT_MAX_AGE_HOURS, now: datetime | None = None) -> SecurityGateResult:
    gate_id = "PB-SEC-002"
    payload, blocked = _load_gate_payload(root, gate_id)
    if blocked:
        return blocked
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    errors = _common_errors(gate_id, payload, max_age_hours=max_age_hours, now=effective_now)
    _require_bool(errors, payload, "scan_completed", True, "PBSEC002_SCAN_NOT_COMPLETED")
    _require_bool(errors, payload, "raw_payload_logged", False, "PBSEC002_RAW_PAYLOAD_LOGGED")
    _require_non_empty_string(errors, payload, "report_hash", "PBSEC002_REPORT_HASH_MISSING")
    _require_non_negative_int(errors, payload, "critical_findings", "PBSEC002_CRITICAL_FINDINGS_INVALID")
    _require_non_negative_int(errors, payload, "high_findings", "PBSEC002_HIGH_FINDINGS_INVALID")
    sources = payload.get("sources", {})
    if not isinstance(sources, dict) or not any(bool(value) for value in sources.values()):
        errors.append("PBSEC002_DEPENDENCY_EVIDENCE_MISSING")
    if "dependency_lockfile_present" in payload and payload.get("dependency_lockfile_present") is not True:
        errors.append("PBSEC002_DEPENDENCY_LOCKFILE_MISSING")
    if _int_value(payload, "critical_findings") > 0:
        errors.append("PBSEC002_CRITICAL_DEPENDENCY_FINDING")
    if _int_value(payload, "high_findings") > 0:
        errors.append("PBSEC002_HIGH_DEPENDENCY_FINDING")
    return _finalize(gate_id, payload, errors)


def evaluate_authentication_gate(root: Path, *, max_age_hours: float = DEFAULT_MAX_AGE_HOURS, now: datetime | None = None) -> SecurityGateResult:
    gate_id = "PB-SEC-003"
    payload, blocked = _load_gate_payload(root, gate_id)
    if blocked:
        return blocked
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    errors = _common_errors(gate_id, payload, max_age_hours=max_age_hours, now=effective_now)
    _require_bool(errors, payload, "auth_bypass_detected", False, "PBSEC003_AUTH_BYPASS_DETECTED")
    _require_bool(errors, payload, "replay_acceptance_detected", False, "PBSEC003_REPLAY_ACCEPTANCE_DETECTED")
    _require_bool(errors, payload, "nonce_required", True, "PBSEC003_NONCE_REQUIRED_MISSING")
    _require_bool(errors, payload, "challenge_expiry_verified", True, "PBSEC003_CHALLENGE_EXPIRY_MISSING")
    _require_bool(errors, payload, "session_expiry_verified", True, "PBSEC003_SESSION_EXPIRY_MISSING")
    _require_bool(errors, payload, "privileged_route_protected", True, "PBSEC003_PRIVILEGED_ROUTE_UNPROTECTED")
    _require_non_empty_string(errors, payload, "report_hash", "PBSEC003_REPORT_HASH_MISSING")
    return _finalize(gate_id, payload, errors)


def evaluate_external_pentest_gate(root: Path, *, max_age_hours: float = DEFAULT_MAX_AGE_HOURS, now: datetime | None = None) -> SecurityGateResult:
    gate_id = "PB-SEC-004"
    payload, blocked = _load_gate_payload(root, gate_id)
    if blocked:
        return blocked
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    errors = _common_errors(gate_id, payload, max_age_hours=max_age_hours, now=effective_now)
    _require_bool(errors, payload, "pentest_completed", True, "PBSEC004_PENTEST_NOT_COMPLETED")
    _require_bool(errors, payload, "remediation_completed", True, "PBSEC004_REMEDIATION_INCOMPLETE")
    _require_non_empty_string(errors, payload, "provider_or_reviewer", "PBSEC004_PROVIDER_OR_REVIEWER_MISSING")
    _require_non_empty_string(errors, payload, "approval_signature_or_hash", "PBSEC004_APPROVAL_SIGNATURE_MISSING")
    _require_timestamp(
        errors,
        payload,
        "approved_at",
        "PBSEC004_APPROVED_AT_INVALID",
        stale_code="PBSEC004_APPROVAL_STALE",
        max_age_hours=max_age_hours,
        now=effective_now,
    )
    _require_non_negative_int(errors, payload, "unresolved_critical_findings", "PBSEC004_UNRESOLVED_CRITICAL_INVALID")
    _require_non_negative_int(errors, payload, "unresolved_high_findings", "PBSEC004_UNRESOLVED_HIGH_INVALID")
    if _int_value(payload, "unresolved_critical_findings") > 0:
        errors.append("PBSEC004_UNRESOLVED_CRITICAL_FINDINGS")
    if _int_value(payload, "unresolved_high_findings") > 0:
        errors.append("PBSEC004_UNRESOLVED_HIGH_FINDINGS")
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
    _require_bool(errors, payload, "human_approved", True, "PBSEC005_HUMAN_APPROVAL_MISSING")
    _require_bool(errors, payload, "no_ai_auto_approval", True, "PBSEC005_AI_AUTO_APPROVAL_NOT_REJECTED")
    if payload.get("approver_role") != "authorized-human-reviewer":
        errors.append("PBSEC005_APPROVER_ROLE_UNAUTHORIZED")
    if payload.get("approved_scope") != "production-release":
        errors.append("PBSEC005_APPROVED_SCOPE_INVALID")
    _require_non_empty_string(errors, payload, "approval_signature_or_hash", "PBSEC005_APPROVAL_SIGNATURE_MISSING")
    _require_timestamp(
        errors,
        payload,
        "approved_at",
        "PBSEC005_APPROVED_AT_INVALID",
        stale_code="PBSEC005_APPROVAL_STALE",
        max_age_hours=max_age_hours,
        now=effective_now,
    )
    approver_actor = str(payload.get("approver_actor", "")).lower()
    if approver_actor in {"ai", "codex", "assistant", "automation"}:
        errors.append("PBSEC005_AI_APPROVER_REJECTED")
    linkage = payload.get("evidence_hash_linkage")
    required_linkage = {"PB-020", "PB-SEC-001", "PB-SEC-002", "PB-SEC-003", "PB-SEC-004"}
    if not isinstance(linkage, dict) or set(linkage) < required_linkage:
        errors.append("PBSEC005_EVIDENCE_LINKAGE_INCOMPLETE")
    elif any(not isinstance(linkage.get(key), str) or not linkage.get(key, "").strip() for key in required_linkage):
        errors.append("PBSEC005_EVIDENCE_LINKAGE_INVALID")
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
