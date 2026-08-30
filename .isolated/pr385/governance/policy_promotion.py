from __future__ import annotations

from typing import Any

from governance.policy_registry_contracts import build_policy_audit_record, validate_policy_record
from governance.policy_versioning import validate_policy_transition


PROMOTION_TRANSITIONS = {("DRAFT", "REVIEW_REQUIRED"), ("REVIEW_REQUIRED", "APPROVED"), ("APPROVED", "ACTIVE")}


def evaluate_policy_promotion(
    *,
    policy: dict[str, Any] | None,
    target_status: str,
    human_approval: dict[str, Any] | None,
    audit_record: dict[str, Any] | None,
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_policy_record(policy)
    if not validation.valid:
        reasons.extend(validation.reason_codes)
    current_status = str(policy.get("status", "") if isinstance(policy, dict) else "")
    transition = validate_policy_transition(current_status, target_status)
    if transition["transition_status"] != "ALLOWED" or (current_status, target_status) not in PROMOTION_TRANSITIONS:
        reasons.extend(transition["reason_codes"] or [f"POLICY_PROMOTION_INVALID:{current_status}->{target_status}"])
    if not isinstance(human_approval, dict) or human_approval.get("approved") is not True:
        reasons.append("POLICY_HUMAN_APPROVAL_MISSING")
    if not isinstance(human_approval, dict) or not str(human_approval.get("approved_by", "")).strip():
        reasons.append("POLICY_APPROVED_BY_MISSING")
    if not isinstance(audit_record, dict) or not str(audit_record.get("audit_hash", "")).strip():
        reasons.append("POLICY_PROMOTION_AUDIT_RECORD_MISSING")
    if not isinstance(policy, dict) or not str(policy.get("policy_hash", "")).strip():
        reasons.append("POLICY_HASH_MISSING")
    if not isinstance(policy, dict) or not str(policy.get("policy_version", "")).strip():
        reasons.append("POLICY_VERSION_MISSING")
    decision = "BLOCKED" if reasons else "PROMOTION_ALLOWED"
    return {
        "schema": "usbay.policy.promotion.v1",
        "promotion_status": decision,
        "from_status": current_status,
        "to_status": str(target_status),
        "reason_codes": sorted(set(reasons)),
        "audit_record": build_policy_audit_record(policy=policy, action="promotion", reason_codes=reasons),
        "auto_promoted": False,
        "auto_approved": False,
        "auto_activated": False,
    }
