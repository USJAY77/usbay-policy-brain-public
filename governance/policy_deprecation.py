from __future__ import annotations

from typing import Any

from governance.policy_registry_contracts import build_policy_audit_record, validate_policy_record
from governance.policy_versioning import validate_policy_transition


DEPRECATION_TRANSITIONS = {("ACTIVE", "DEPRECATED"), ("DEPRECATED", "RETIRED")}


def evaluate_policy_deprecation(
    *,
    policy: dict[str, Any] | None,
    target_status: str,
    reason: str,
    replacement_policy_id: str,
    audit_record: dict[str, Any] | None,
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_policy_record(policy)
    if not validation.valid:
        reasons.extend(validation.reason_codes)
    current_status = str(policy.get("status", "") if isinstance(policy, dict) else "")
    transition = validate_policy_transition(current_status, target_status)
    if transition["transition_status"] != "ALLOWED" or (current_status, target_status) not in DEPRECATION_TRANSITIONS:
        reasons.extend(transition["reason_codes"] or [f"POLICY_DEPRECATION_INVALID:{current_status}->{target_status}"])
    if not str(reason).strip():
        reasons.append("POLICY_DEPRECATION_REASON_MISSING")
    if not str(replacement_policy_id).strip():
        reasons.append("POLICY_REPLACEMENT_POLICY_MISSING")
    if not isinstance(audit_record, dict) or not str(audit_record.get("audit_hash", "")).strip():
        reasons.append("POLICY_DEPRECATION_AUDIT_RECORD_MISSING")
    return {
        "schema": "usbay.policy.deprecation.v1",
        "deprecation_status": "BLOCKED" if reasons else "DEPRECATION_ALLOWED",
        "from_status": current_status,
        "to_status": str(target_status),
        "replacement_policy_id": str(replacement_policy_id),
        "reason_codes": sorted(set(reasons)),
        "audit_record": build_policy_audit_record(policy=policy, action="deprecation", reason_codes=reasons),
        "auto_retired": False,
        "auto_promoted": False,
        "auto_approved": False,
    }
