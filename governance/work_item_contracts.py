from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


WORK_ITEM_SCHEMA = "usbay.work_item.v1"
WORK_ASSIGNMENT_SCHEMA = "usbay.work_assignment.v1"
WORK_RESOLUTION_SCHEMA = "usbay.work_resolution.v1"
WORK_CLOSURE_SCHEMA = "usbay.work_closure.v1"
WORK_POLICY_VERSION = "usbay.pb-work.governed-work-orchestrator.v1"

WORK_STATUSES = frozenset({"NEW", "ASSIGNED", "IN_PROGRESS", "ESCALATED", "RESOLVED", "CLOSED"})
SUPPORTED_OWNER_ROLES = frozenset({"USBAY_OPERATOR", "USBAY_AUDITOR", "USBAY_ADMIN"})
UNSUPPORTED_OWNER_ROLES = frozenset({"AI_AGENT", "CODEX", "AUTOMATION", "SYSTEM"})

REQUIRED_WORK_FIELDS = (
    "work_item_id",
    "source_review_id",
    "source_request_id",
    "source_proposal_id",
    "source_decision_id",
    "owner_id",
    "owner_role",
    "priority",
    "severity",
    "created_at",
    "assigned_at",
    "resolved_at",
    "closed_at",
    "status",
    "audit_hash",
    "lineage_hash",
    "policy_version",
    "fail_closed",
)

REQUIRED_ESCALATION_FIELDS = (
    "escalation_id",
    "work_item_id",
    "reason",
    "requested_by",
    "timestamp",
    "target_role",
    "audit_hash",
    "policy_version",
)


@dataclass(frozen=True)
class WorkItemValidation:
    valid: bool
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "reason_codes": list(self.reason_codes)}


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def owner_role_authorized(owner_role: Any) -> tuple[bool, tuple[str, ...]]:
    role = str(owner_role or "").strip().upper()
    if not role:
        return False, ("WORK_OWNER_ROLE_MISSING",)
    if role in UNSUPPORTED_OWNER_ROLES:
        return False, (f"WORK_OWNER_ROLE_REJECTED:{role}",)
    if role not in SUPPORTED_OWNER_ROLES:
        return False, (f"WORK_OWNER_ROLE_UNKNOWN:{role}",)
    return True, ()


def _missing_fields(payload: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    return [field for field in required if payload.get(field) in ("", None)]


def validate_work_item(work_item: dict[str, Any] | None, *, expected_schema: str = WORK_ITEM_SCHEMA) -> WorkItemValidation:
    if not isinstance(work_item, dict):
        return WorkItemValidation(False, ("WORK_ITEM_MISSING",))

    reasons: list[str] = []
    for field in _missing_fields(work_item, REQUIRED_WORK_FIELDS):
        reasons.append(f"WORK_ITEM_{field.upper()}_MISSING")

    if work_item.get("schema") != expected_schema:
        reasons.append("WORK_ITEM_SCHEMA_INVALID")
    status = str(work_item.get("status", ""))
    if status not in WORK_STATUSES:
        reasons.append(f"WORK_STATUS_UNKNOWN:{status or 'MISSING'}")
    role_valid, role_reasons = owner_role_authorized(work_item.get("owner_role"))
    if not role_valid:
        reasons.extend(role_reasons)
    for field in ("created_at", "assigned_at", "resolved_at", "closed_at"):
        if parse_timestamp(work_item.get(field)) is None:
            reasons.append(f"WORK_ITEM_{field.upper()}_INVALID")
    if not str(work_item.get("audit_hash", "")).strip():
        reasons.append("WORK_AUDIT_HASH_MISSING")
    if not str(work_item.get("lineage_hash", "")).strip():
        reasons.append("WORK_LINEAGE_HASH_MISSING")
    if not str(work_item.get("policy_version", "")).strip():
        reasons.append("WORK_POLICY_VERSION_MISSING")
    if work_item.get("fail_closed") is not False and status in {"ASSIGNED", "IN_PROGRESS", "RESOLVED", "CLOSED"}:
        reasons.append("WORK_NON_BLOCKED_STATUS_FAIL_CLOSED")

    return WorkItemValidation(not reasons, tuple(sorted(set(reasons))))


def validate_work_assignment(work_item: dict[str, Any] | None) -> WorkItemValidation:
    return validate_work_item(work_item, expected_schema=WORK_ASSIGNMENT_SCHEMA)


def validate_work_resolution(work_item: dict[str, Any] | None) -> WorkItemValidation:
    return validate_work_item(work_item, expected_schema=WORK_RESOLUTION_SCHEMA)


def validate_work_closure(work_item: dict[str, Any] | None) -> WorkItemValidation:
    return validate_work_item(work_item, expected_schema=WORK_CLOSURE_SCHEMA)


def validate_escalation(escalation: dict[str, Any] | None) -> WorkItemValidation:
    if not isinstance(escalation, dict):
        return WorkItemValidation(False, ("WORK_ESCALATION_MISSING",))
    reasons: list[str] = []
    for field in _missing_fields(escalation, REQUIRED_ESCALATION_FIELDS):
        reasons.append(f"WORK_ESCALATION_{field.upper()}_MISSING")
    role_valid, role_reasons = owner_role_authorized(escalation.get("target_role"))
    if not role_valid:
        reasons.extend(role_reasons)
    if parse_timestamp(escalation.get("timestamp")) is None:
        reasons.append("WORK_ESCALATION_TIMESTAMP_INVALID")
    if not str(escalation.get("audit_hash", "")).strip():
        reasons.append("WORK_ESCALATION_AUDIT_HASH_MISSING")
    return WorkItemValidation(not reasons, tuple(sorted(set(reasons))))


def build_work_audit_record(
    *,
    work_item: dict[str, Any] | None,
    status: str,
    reason_codes: list[str] | tuple[str, ...],
    previous_hash: str = "",
    generated_at: str,
) -> dict[str, Any]:
    safe_work = work_item if isinstance(work_item, dict) else {}
    record = {
        "schema": "usbay.work_audit.v1",
        "work_item_id": str(safe_work.get("work_item_id", "")),
        "source_review_id": str(safe_work.get("source_review_id", "")),
        "source_request_id": str(safe_work.get("source_request_id", "")),
        "source_proposal_id": str(safe_work.get("source_proposal_id", "")),
        "source_decision_id": str(safe_work.get("source_decision_id", "")),
        "owner_id_hash": sha256_json(str(safe_work.get("owner_id", ""))) if safe_work.get("owner_id") else "",
        "owner_role": str(safe_work.get("owner_role", "")),
        "status": str(status),
        "reason_codes": sorted({str(code) for code in reason_codes if code}),
        "previous_hash": str(previous_hash),
        "policy_version": str(safe_work.get("policy_version", WORK_POLICY_VERSION)),
        "generated_at": str(generated_at),
        "audit_hash": "",
        "fail_closed": str(status) == "BLOCKED",
        "secrets_logged": False,
        "raw_payload_logged": False,
        "auto_assigned": False,
        "auto_resolved": False,
        "auto_closed": False,
        "auto_escalated": False,
    }
    record["audit_hash"] = sha256_json(record | {"audit_hash": ""})
    return record


def work_hash(work_item: dict[str, Any]) -> str:
    return sha256_json({key: value for key, value in work_item.items() if key != "audit_hash"})
