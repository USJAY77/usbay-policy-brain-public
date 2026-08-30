from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


OPERATOR_REVIEW_REQUEST_SCHEMA = "usbay.operator.review_request.v1"
OPERATOR_REVIEW_DECISION_SCHEMA = "usbay.operator.review_decision.v1"
OPERATOR_REVIEW_AUDIT_SCHEMA = "usbay.operator.review_audit.v1"
OPERATOR_REVIEW_POLICY_VERSION = "usbay.pb-op.governed-operator-review-queue.v1"

QUEUE_STATES = frozenset(
    {
        "PENDING_REVIEW",
        "UNDER_REVIEW",
        "APPROVED",
        "REJECTED",
        "NEEDS_INFORMATION",
        "BLOCKED",
    }
)
ALLOWED_DECISIONS = frozenset({"APPROVED", "REJECTED", "NEEDS_INFORMATION"})
TERMINAL_DECISION_STATES = frozenset({"APPROVED", "REJECTED", "NEEDS_INFORMATION"})
AUTHORIZED_OPERATOR_ROLES = frozenset({"USBAY_OPERATOR", "USBAY_AUDITOR", "USBAY_ADMIN"})
REJECTED_OPERATOR_ROLES = frozenset({"CODEX", "AI_AGENT", "AUTOMATION", "SYSTEM"})

REQUIRED_REVIEW_FIELDS = (
    "review_id",
    "request_id",
    "proposal_id",
    "approval_id",
    "operator_id",
    "operator_role",
    "review_state",
    "decision",
    "decision_reason",
    "decision_timestamp",
    "audit_hash",
    "previous_hash",
    "fail_closed",
    "policy_version",
)


@dataclass(frozen=True)
class OperatorReviewValidation:
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


def missing_review_fields(review: dict[str, Any]) -> list[str]:
    return [field for field in REQUIRED_REVIEW_FIELDS if review.get(field) in ("", None)]


def operator_role_authorized(operator_role: Any) -> tuple[bool, tuple[str, ...]]:
    role = str(operator_role or "").strip().upper()
    if not role:
        return False, ("OPERATOR_ROLE_MISSING",)
    if role in REJECTED_OPERATOR_ROLES:
        return False, (f"OPERATOR_ROLE_REJECTED:{role}",)
    if role not in AUTHORIZED_OPERATOR_ROLES:
        return False, (f"OPERATOR_ROLE_UNKNOWN:{role}",)
    return True, ()


def validate_operator_review_payload(review: dict[str, Any] | None, *, expected_schema: str) -> OperatorReviewValidation:
    if not isinstance(review, dict):
        return OperatorReviewValidation(False, ("OPERATOR_REVIEW_MISSING",))

    reasons: list[str] = []
    for field in missing_review_fields(review):
        reasons.append(f"OPERATOR_REVIEW_{field.upper()}_MISSING")

    if review.get("schema") != expected_schema:
        reasons.append("OPERATOR_REVIEW_SCHEMA_INVALID")

    review_state = str(review.get("review_state", ""))
    decision = str(review.get("decision", ""))
    if review_state not in QUEUE_STATES:
        reasons.append(f"OPERATOR_REVIEW_STATE_UNKNOWN:{review_state or 'MISSING'}")
    if decision not in ALLOWED_DECISIONS:
        reasons.append(f"OPERATOR_REVIEW_DECISION_UNKNOWN:{decision or 'MISSING'}")
    if review_state in TERMINAL_DECISION_STATES and review_state != decision:
        reasons.append("OPERATOR_REVIEW_STATE_DECISION_MISMATCH")

    role_valid, role_reasons = operator_role_authorized(review.get("operator_role"))
    if not role_valid:
        reasons.extend(role_reasons)

    if parse_timestamp(review.get("decision_timestamp")) is None:
        reasons.append("OPERATOR_REVIEW_DECISION_TIMESTAMP_INVALID")
    if not str(review.get("audit_hash", "")).strip():
        reasons.append("OPERATOR_REVIEW_AUDIT_HASH_MISSING")
    if not str(review.get("policy_version", "")).strip():
        reasons.append("OPERATOR_REVIEW_POLICY_VERSION_MISSING")
    if review.get("fail_closed") is not False and review_state == "APPROVED":
        reasons.append("OPERATOR_REVIEW_APPROVAL_FAIL_CLOSED")

    return OperatorReviewValidation(not reasons, tuple(sorted(set(reasons))))


def validate_review_request(review: dict[str, Any] | None) -> OperatorReviewValidation:
    return validate_operator_review_payload(review, expected_schema=OPERATOR_REVIEW_REQUEST_SCHEMA)


def validate_review_decision(review: dict[str, Any] | None) -> OperatorReviewValidation:
    return validate_operator_review_payload(review, expected_schema=OPERATOR_REVIEW_DECISION_SCHEMA)


def build_operator_review_audit(
    *,
    review: dict[str, Any] | None,
    decision: str,
    reason_codes: list[str] | tuple[str, ...],
    previous_hash: str = "",
    generated_at: str,
) -> dict[str, Any]:
    safe_review = review if isinstance(review, dict) else {}
    record = {
        "schema": OPERATOR_REVIEW_AUDIT_SCHEMA,
        "review_id": str(safe_review.get("review_id", "")),
        "request_id": str(safe_review.get("request_id", "")),
        "proposal_id": str(safe_review.get("proposal_id", "")),
        "approval_id": str(safe_review.get("approval_id", "")),
        "operator_id_hash": sha256_json(str(safe_review.get("operator_id", ""))) if safe_review.get("operator_id") else "",
        "operator_role": str(safe_review.get("operator_role", "")),
        "review_state": str(safe_review.get("review_state", "")),
        "decision": str(decision),
        "decision_reason": str(safe_review.get("decision_reason", "")),
        "reason_codes": sorted({str(code) for code in reason_codes if code}),
        "previous_hash": str(previous_hash),
        "policy_version": str(safe_review.get("policy_version", OPERATOR_REVIEW_POLICY_VERSION)),
        "generated_at": str(generated_at),
        "audit_hash": "",
        "fail_closed": str(decision) != "APPROVED",
        "secrets_logged": False,
        "raw_payload_logged": False,
        "auto_approved": False,
        "auto_executed": False,
    }
    record["audit_hash"] = sha256_json(record | {"audit_hash": ""})
    return record


def review_hash(review: dict[str, Any]) -> str:
    return sha256_json({key: value for key, value in review.items() if key != "audit_hash"})
