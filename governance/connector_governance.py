from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.connector_contracts import build_connector_audit_record, validate_read_request, validate_read_result
from governance.connector_registry import connector_available


DECISION_ALLOWED_READ_ONLY = "CONNECTOR_READ_ALLOWED"
DECISION_BLOCKED = "CONNECTOR_BLOCKED"


@dataclass(frozen=True)
class ConnectorGovernanceResult:
    decision: str
    reason_codes: tuple[str, ...]
    audit_record: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "reason_codes": list(self.reason_codes), "audit_record": self.audit_record}


def _now_text(now: datetime | None) -> str:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return effective_now.isoformat().replace("+00:00", "Z")


def _append_reason(reasons: list[str], code: str) -> None:
    if code not in reasons:
        reasons.append(code)


def evaluate_connector_read_request(
    *,
    request: dict[str, Any] | None,
    registry: dict[str, Any] | None,
    now: datetime | None = None,
) -> ConnectorGovernanceResult:
    generated_at = _now_text(now)
    reasons: list[str] = []
    validation = validate_read_request(request)
    if not validation.valid:
        reasons.extend(validation.reason_codes)
    connector_type = str(request.get("connector_type", "") if isinstance(request, dict) else "")
    available, availability_reasons = connector_available(registry, connector_type)
    if not available:
        reasons.extend(availability_reasons)
    decision = DECISION_BLOCKED if reasons else DECISION_ALLOWED_READ_ONLY
    audit = build_connector_audit_record(request=request, decision=decision, reason_codes=reasons, generated_at=generated_at)
    return ConnectorGovernanceResult(decision=decision, reason_codes=tuple(sorted(set(reasons))), audit_record=audit)


def evaluate_connector_read_result(result: dict[str, Any] | None) -> tuple[bool, tuple[str, ...]]:
    validation = validate_read_result(result)
    if not validation.valid:
        return False, validation.reason_codes
    if not str(result.get("evidence_manifest_id", "")).strip():
        return False, ("CONNECTOR_EVIDENCE_MANIFEST_ID_MISSING",)
    if not str(result.get("audit_hash", "")).strip():
        return False, ("CONNECTOR_AUDIT_HASH_MISSING",)
    if not str(result.get("lineage_hash", "")).strip():
        return False, ("CONNECTOR_LINEAGE_HASH_MISSING",)
    if not str(result.get("policy_version", "")).strip():
        return False, ("CONNECTOR_POLICY_VERSION_MISSING",)
    return True, ()
