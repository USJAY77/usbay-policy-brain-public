from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json
from governance.execution_governance import ADAPTER_STATUS, EXECUTION_ENGINE_STATUS
from governance.operator_review_contracts import (
    ALLOWED_DECISIONS,
    QUEUE_STATES,
    build_operator_review_audit,
    operator_role_authorized,
    validate_review_decision,
)


QUEUE_STATE_PENDING = "PENDING_REVIEW"
QUEUE_STATE_UNDER_REVIEW = "UNDER_REVIEW"
QUEUE_STATE_APPROVED = "APPROVED"
QUEUE_STATE_REJECTED = "REJECTED"
QUEUE_STATE_NEEDS_INFORMATION = "NEEDS_INFORMATION"
QUEUE_STATE_BLOCKED = "BLOCKED"

OPERATOR_DECISION_APPROVED = "APPROVED"
OPERATOR_DECISION_REJECTED = "REJECTED"
OPERATOR_DECISION_NEEDS_INFORMATION = "NEEDS_INFORMATION"
OPERATOR_DECISION_BLOCKED = "BLOCKED"

LINEAGE_SCHEMA = "usbay.operator.review_lineage.v1"
AI_OPERATOR_IDS = frozenset({"codex", "ai-agent", "ai_agent", "automation", "system", "assistant"})


@dataclass(frozen=True)
class OperatorQueueResult:
    decision: str
    review_state: str
    reason_codes: tuple[str, ...]
    review: dict[str, Any]
    audit_record: dict[str, Any]
    audit_lineage: dict[str, Any]
    execution_engine_status: str = EXECUTION_ENGINE_STATUS
    adapter_status: str = ADAPTER_STATUS

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "review_state": self.review_state,
            "reason_codes": list(self.reason_codes),
            "review": self.review,
            "audit_record": self.audit_record,
            "audit_lineage": self.audit_lineage,
            "execution_engine_status": self.execution_engine_status,
            "adapter_status": self.adapter_status,
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
    for key in ("timestamp", "generated_at", "created_at", "requested_at", "approved_at", "decision_timestamp"):
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


def build_operator_audit_lineage(
    *,
    observation: dict[str, Any] | None,
    proposal: dict[str, Any] | None,
    request: dict[str, Any] | None,
    approval: dict[str, Any] | None,
    review: dict[str, Any] | None,
    execution_decision: dict[str, Any] | None,
    previous_hash: str,
    generated_at: str,
) -> dict[str, Any]:
    links = (
        ("observation", observation),
        ("proposal", proposal),
        ("request", request),
        ("approval", approval),
        ("review", review),
        ("decision", execution_decision),
    )
    reason_codes: list[str] = []
    link_records: dict[str, dict[str, str]] = {}
    for name, payload in links:
        if not isinstance(payload, dict) or not payload:
            _append_reason(reason_codes, f"OP_LINEAGE_{name.upper()}_MISSING")
            link_records[name] = {"audit_hash": "", "timestamp": "", "policy_version": "", "payload_hash": _safe_hash(payload)}
            continue
        audit_hash = _link_audit_hash(payload)
        timestamp = _link_timestamp(payload)
        policy_version = _link_policy_version(payload)
        if not audit_hash:
            _append_reason(reason_codes, f"OP_LINEAGE_{name.upper()}_AUDIT_HASH_MISSING")
        if not timestamp:
            _append_reason(reason_codes, f"OP_LINEAGE_{name.upper()}_TIMESTAMP_MISSING")
        if not policy_version:
            _append_reason(reason_codes, f"OP_LINEAGE_{name.upper()}_POLICY_VERSION_MISSING")
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


def _operator_is_ai(operator_id: str, operator_role: str) -> bool:
    return operator_id.strip().lower() in AI_OPERATOR_IDS or operator_role.strip().upper() in {
        "CODEX",
        "AI_AGENT",
        "AUTOMATION",
        "SYSTEM",
    }


def _self_approval(review: dict[str, Any], request: dict[str, Any] | None, approval: dict[str, Any] | None) -> bool:
    operator_id = str(review.get("operator_id", ""))
    if not operator_id:
        return False
    if isinstance(request, dict) and operator_id == str(request.get("requested_by", "")):
        return True
    if isinstance(approval, dict) and operator_id in {
        str(approval.get("operator_id", "")),
        str(approval.get("approver_id", "")),
        str(approval.get("approved_by", "")),
    }:
        return True
    return False


def evaluate_operator_review(
    *,
    review: dict[str, Any] | None,
    observation: dict[str, Any] | None = None,
    proposal: dict[str, Any] | None = None,
    request: dict[str, Any] | None = None,
    approval: dict[str, Any] | None = None,
    execution_decision: dict[str, Any] | None = None,
    previous_hash: str = "",
    now: datetime | None = None,
) -> OperatorQueueResult:
    generated_at = _now_text(now)
    reasons: list[str] = []
    safe_review = review if isinstance(review, dict) else {}

    if not isinstance(review, dict):
        _append_reason(reasons, "OP_REVIEW_MISSING")
    else:
        validation = validate_review_decision(review)
        if not validation.valid:
            reasons.extend(validation.reason_codes)

        operator_id = str(review.get("operator_id", ""))
        operator_role = str(review.get("operator_role", ""))
        if not operator_id:
            _append_reason(reasons, "OP_OPERATOR_ID_MISSING")
        role_valid, role_reasons = operator_role_authorized(operator_role)
        if not role_valid:
            reasons.extend(role_reasons)
        if _operator_is_ai(operator_id, operator_role):
            _append_reason(reasons, "OP_AI_OPERATOR_BLOCKED")
        if _self_approval(review, request, approval):
            _append_reason(reasons, "OP_SELF_APPROVAL_BLOCKED")

        review_state = str(review.get("review_state", ""))
        decision = str(review.get("decision", ""))
        if review_state not in QUEUE_STATES:
            _append_reason(reasons, f"OP_QUEUE_STATE_UNKNOWN:{review_state or 'MISSING'}")
        if decision not in ALLOWED_DECISIONS:
            _append_reason(reasons, f"OP_DECISION_UNKNOWN:{decision or 'MISSING'}")
        if not str(review.get("audit_hash", "")).strip():
            _append_reason(reasons, "OP_AUDIT_HASH_MISSING")
        if not str(review.get("policy_version", "")).strip():
            _append_reason(reasons, "OP_POLICY_VERSION_MISSING")

    if not isinstance(approval, dict):
        _append_reason(reasons, "OP_APPROVAL_LINK_MISSING")
    elif isinstance(review, dict) and review.get("approval_id") != approval.get("approval_id"):
        _append_reason(reasons, "OP_APPROVAL_LINK_MISMATCH")

    if not isinstance(request, dict):
        _append_reason(reasons, "OP_EXECUTION_REQUEST_LINK_MISSING")
    elif isinstance(review, dict):
        if review.get("request_id") != request.get("request_id"):
            _append_reason(reasons, "OP_REQUEST_LINK_MISMATCH")
        if review.get("proposal_id") != request.get("proposal_id"):
            _append_reason(reasons, "OP_PROPOSAL_LINK_MISMATCH")

    lineage = build_operator_audit_lineage(
        observation=observation,
        proposal=proposal,
        request=request,
        approval=approval,
        review=review,
        execution_decision=execution_decision,
        previous_hash=previous_hash,
        generated_at=generated_at,
    )
    if lineage["fail_closed"]:
        reasons.extend(str(code) for code in lineage["reason_codes"])

    decision = str(safe_review.get("decision", OPERATOR_DECISION_BLOCKED))
    if reasons:
        final_decision = OPERATOR_DECISION_BLOCKED
        review_state = QUEUE_STATE_BLOCKED
    elif decision == OPERATOR_DECISION_APPROVED:
        final_decision = OPERATOR_DECISION_APPROVED
        review_state = QUEUE_STATE_APPROVED
    elif decision == OPERATOR_DECISION_REJECTED:
        final_decision = OPERATOR_DECISION_REJECTED
        review_state = QUEUE_STATE_REJECTED
    elif decision == OPERATOR_DECISION_NEEDS_INFORMATION:
        final_decision = OPERATOR_DECISION_NEEDS_INFORMATION
        review_state = QUEUE_STATE_NEEDS_INFORMATION
    else:
        final_decision = OPERATOR_DECISION_BLOCKED
        review_state = QUEUE_STATE_BLOCKED

    audit = build_operator_review_audit(
        review=review,
        decision=final_decision,
        reason_codes=reasons,
        previous_hash=previous_hash,
        generated_at=generated_at,
    )
    return OperatorQueueResult(
        decision=final_decision,
        review_state=review_state,
        reason_codes=tuple(sorted(set(reasons))),
        review=safe_review,
        audit_record=audit,
        audit_lineage=lineage,
    )


def empty_operator_queue_dashboard_state() -> dict[str, Any]:
    result = evaluate_operator_review(review=None)
    return {
        "schema_version": "usbay.operator.queue.demo_dashboard_state.v1",
        "review_id": "",
        "operator_role": "",
        "review_state": result.review_state,
        "decision": result.decision,
        "decision_reason": "Missing operator review blocks execution finalization",
        "review_timestamp": "",
        "queue_counts": {
            "pending": 0,
            "approved": 0,
            "rejected": 0,
            "needs_information": 0,
        },
        "reason_codes": list(result.reason_codes),
        "audit_hash": result.audit_record["audit_hash"],
        "lineage_hash": result.audit_lineage["lineage_hash"],
        "execution_engine_status": EXECUTION_ENGINE_STATUS,
        "adapter_status": ADAPTER_STATUS,
        "auto_approved": False,
        "auto_executed": False,
        "auto_released": False,
    }
