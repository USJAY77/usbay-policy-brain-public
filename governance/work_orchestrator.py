from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json
from governance.work_item_contracts import (
    SUPPORTED_OWNER_ROLES,
    UNSUPPORTED_OWNER_ROLES,
    WORK_POLICY_VERSION,
    WORK_STATUSES,
    build_work_audit_record,
    owner_role_authorized,
    validate_escalation,
    validate_work_item,
)


WORK_STATUS_BLOCKED = "BLOCKED"
LINEAGE_SCHEMA = "usbay.work_orchestrator.lineage.v1"
AI_OWNER_IDS = frozenset({"ai-agent", "ai_agent", "codex", "automation", "system", "assistant"})

ALLOWED_TRANSITIONS = {
    "NEW": frozenset({"ASSIGNED", "ESCALATED"}),
    "ASSIGNED": frozenset({"IN_PROGRESS", "ESCALATED"}),
    "IN_PROGRESS": frozenset({"RESOLVED", "ESCALATED"}),
    "RESOLVED": frozenset({"CLOSED"}),
}


@dataclass(frozen=True)
class WorkOrchestrationResult:
    status: str
    reason_codes: tuple[str, ...]
    work_item: dict[str, Any]
    audit_record: dict[str, Any]
    audit_lineage: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_codes": list(self.reason_codes),
            "work_item": self.work_item,
            "audit_record": self.audit_record,
            "audit_lineage": self.audit_lineage,
        }


def _now_text(now: datetime | None) -> str:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return effective_now.isoformat().replace("+00:00", "Z")


def _append_reason(reasons: list[str], code: str) -> None:
    if code not in reasons:
        reasons.append(code)


def _safe_hash(value: Any) -> str:
    return sha256_json(value if isinstance(value, dict) else {})


def _link_timestamp(link: dict[str, Any]) -> str:
    for key in (
        "timestamp",
        "generated_at",
        "created_at",
        "requested_at",
        "approved_at",
        "decision_timestamp",
        "assigned_at",
        "resolved_at",
        "closed_at",
    ):
        value = link.get(key)
        if value:
            return str(value)
    return ""


def _link_policy_version(link: dict[str, Any]) -> str:
    return str(link.get("policy_version", ""))


def _link_audit_hash(link: dict[str, Any]) -> str:
    for key in ("audit_hash", "vision_audit_hash", "execution_audit_hash", "lineage_hash"):
        value = link.get(key)
        if value:
            return str(value)
    return ""


def build_work_audit_lineage(
    *,
    observation: dict[str, Any] | None,
    proposal: dict[str, Any] | None,
    request: dict[str, Any] | None,
    approval: dict[str, Any] | None,
    review: dict[str, Any] | None,
    decision: dict[str, Any] | None,
    work_item: dict[str, Any] | None,
    assignment: dict[str, Any] | None,
    resolution: dict[str, Any] | None,
    closure: dict[str, Any] | None,
    previous_hash: str,
    generated_at: str,
) -> dict[str, Any]:
    links = (
        ("observation", observation),
        ("proposal", proposal),
        ("request", request),
        ("approval", approval),
        ("review", review),
        ("decision", decision),
        ("work_item", work_item),
        ("assignment", assignment),
        ("resolution", resolution),
        ("closure", closure),
    )
    reason_codes: list[str] = []
    link_records: dict[str, dict[str, str]] = {}
    for name, payload in links:
        if not isinstance(payload, dict) or not payload:
            _append_reason(reason_codes, f"WORK_LINEAGE_{name.upper()}_MISSING")
            link_records[name] = {"audit_hash": "", "timestamp": "", "policy_version": "", "payload_hash": _safe_hash(payload)}
            continue
        audit_hash = _link_audit_hash(payload)
        timestamp = _link_timestamp(payload)
        policy_version = _link_policy_version(payload)
        if not audit_hash:
            _append_reason(reason_codes, f"WORK_LINEAGE_{name.upper()}_AUDIT_HASH_MISSING")
        if not timestamp:
            _append_reason(reason_codes, f"WORK_LINEAGE_{name.upper()}_TIMESTAMP_MISSING")
        if not policy_version:
            _append_reason(reason_codes, f"WORK_LINEAGE_{name.upper()}_POLICY_VERSION_MISSING")
        link_records[name] = {
            "audit_hash": audit_hash,
            "timestamp": timestamp,
            "policy_version": policy_version,
            "payload_hash": _safe_hash(payload),
        }
    lineage = {
        "schema": LINEAGE_SCHEMA,
        "links": link_records,
        "previous_hash": str(previous_hash),
        "generated_at": str(generated_at),
        "lineage_hash": "",
        "fail_closed": bool(reason_codes),
        "reason_codes": sorted(reason_codes),
        "secrets_logged": False,
        "raw_payload_logged": False,
    }
    lineage["lineage_hash"] = sha256_json(lineage | {"lineage_hash": ""})
    return lineage


def _owner_is_ai(owner_id: str, owner_role: str) -> bool:
    return owner_id.strip().lower() in AI_OWNER_IDS or owner_role.strip().upper() in UNSUPPORTED_OWNER_ROLES


def _transition_valid(current_status: str, next_status: str) -> bool:
    if current_status == next_status and next_status in WORK_STATUSES:
        return True
    return next_status in ALLOWED_TRANSITIONS.get(current_status, frozenset())


def evaluate_work_transition(
    *,
    work_item: dict[str, Any] | None,
    next_status: str,
    observation: dict[str, Any] | None = None,
    proposal: dict[str, Any] | None = None,
    request: dict[str, Any] | None = None,
    approval: dict[str, Any] | None = None,
    review: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    assignment: dict[str, Any] | None = None,
    escalation: dict[str, Any] | None = None,
    resolution: dict[str, Any] | None = None,
    closure: dict[str, Any] | None = None,
    previous_hash: str = "",
    now: datetime | None = None,
) -> WorkOrchestrationResult:
    generated_at = _now_text(now)
    reasons: list[str] = []
    safe_work = work_item if isinstance(work_item, dict) else {}

    if not isinstance(work_item, dict):
        _append_reason(reasons, "WORK_ITEM_MISSING")
    else:
        validation = validate_work_item(work_item)
        if not validation.valid:
            reasons.extend(validation.reason_codes)
        owner_id = str(work_item.get("owner_id", ""))
        owner_role = str(work_item.get("owner_role", ""))
        if not owner_id:
            _append_reason(reasons, "WORK_OWNER_MISSING")
        role_valid, role_reasons = owner_role_authorized(owner_role)
        if not role_valid:
            reasons.extend(role_reasons)
        if _owner_is_ai(owner_id, owner_role):
            _append_reason(reasons, "WORK_AI_OWNERSHIP_BLOCKED")
        if not str(work_item.get("audit_hash", "")).strip():
            _append_reason(reasons, "WORK_AUDIT_HASH_MISSING")
        if not str(work_item.get("lineage_hash", "")).strip():
            _append_reason(reasons, "WORK_LINEAGE_HASH_MISSING")
        if not str(work_item.get("policy_version", "")).strip():
            _append_reason(reasons, "WORK_POLICY_VERSION_MISSING")

    current_status = str(safe_work.get("status", ""))
    requested_status = str(next_status or "")
    if current_status not in WORK_STATUSES:
        _append_reason(reasons, f"WORK_STATE_UNKNOWN:{current_status or 'MISSING'}")
    if requested_status not in WORK_STATUSES:
        _append_reason(reasons, f"WORK_NEXT_STATE_UNKNOWN:{requested_status or 'MISSING'}")
    elif current_status in WORK_STATUSES and not _transition_valid(current_status, requested_status):
        _append_reason(reasons, f"WORK_INVALID_TRANSITION:{current_status}->{requested_status}")

    if requested_status == "ESCALATED":
        escalation_validation = validate_escalation(escalation)
        if not escalation_validation.valid:
            reasons.extend(escalation_validation.reason_codes)

    if requested_status in {"RESOLVED", "CLOSED"} and not isinstance(resolution, dict):
        _append_reason(reasons, "WORK_RESOLUTION_MISSING")
    if requested_status == "CLOSED":
        if current_status != "RESOLVED":
            _append_reason(reasons, "WORK_CLOSURE_REQUIRES_RESOLVED_STATUS")
        if not isinstance(decision, dict):
            _append_reason(reasons, "WORK_DECISION_MISSING")
        if not isinstance(closure, dict):
            _append_reason(reasons, "WORK_CLOSURE_MISSING")

    lineage = build_work_audit_lineage(
        observation=observation,
        proposal=proposal,
        request=request,
        approval=approval,
        review=review,
        decision=decision,
        work_item=work_item,
        assignment=assignment,
        resolution=resolution,
        closure=closure,
        previous_hash=previous_hash,
        generated_at=generated_at,
    )
    if lineage["fail_closed"]:
        reasons.extend(str(code) for code in lineage["reason_codes"])

    final_status = WORK_STATUS_BLOCKED if reasons else requested_status
    audit = build_work_audit_record(
        work_item=work_item,
        status=final_status,
        reason_codes=reasons,
        previous_hash=previous_hash,
        generated_at=generated_at,
    )
    return WorkOrchestrationResult(
        status=final_status,
        reason_codes=tuple(sorted(set(reasons))),
        work_item=safe_work,
        audit_record=audit,
        audit_lineage=lineage,
    )


def empty_work_orchestrator_dashboard_state() -> dict[str, Any]:
    result = evaluate_work_transition(work_item=None, next_status="NEW")
    return {
        "schema_version": "usbay.work_orchestrator.demo_dashboard_state.v1",
        "work_item_id": "",
        "owner": "",
        "role": "",
        "priority": "",
        "severity": "",
        "status": result.status,
        "created_at": "",
        "assigned_at": "",
        "resolved_at": "",
        "closed_at": "",
        "queue_counts": {
            "new": 0,
            "assigned": 0,
            "in_progress": 0,
            "escalated": 0,
            "resolved": 0,
            "closed": 0,
        },
        "reason_codes": list(result.reason_codes),
        "audit_hash": result.audit_record["audit_hash"],
        "lineage_hash": result.audit_lineage["lineage_hash"],
        "supported_owner_roles": sorted(SUPPORTED_OWNER_ROLES),
        "auto_assigned": False,
        "auto_resolved": False,
        "auto_closed": False,
        "auto_escalated": False,
    }
