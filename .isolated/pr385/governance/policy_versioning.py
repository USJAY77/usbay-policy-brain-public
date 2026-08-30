from __future__ import annotations

from typing import Any


POLICY_STATES = ("DRAFT", "REVIEW_REQUIRED", "APPROVED", "ACTIVE", "DEPRECATED", "RETIRED")
ALLOWED_TRANSITIONS = {
    "DRAFT": {"REVIEW_REQUIRED"},
    "REVIEW_REQUIRED": {"APPROVED"},
    "APPROVED": {"ACTIVE"},
    "ACTIVE": {"DEPRECATED"},
    "DEPRECATED": {"RETIRED"},
    "RETIRED": set(),
}


def validate_policy_transition(from_status: str, to_status: str) -> dict[str, Any]:
    reasons: list[str] = []
    if from_status not in POLICY_STATES:
        reasons.append(f"POLICY_FROM_STATUS_UNKNOWN:{from_status or 'MISSING'}")
    if to_status not in POLICY_STATES:
        reasons.append(f"POLICY_TO_STATUS_UNKNOWN:{to_status or 'MISSING'}")
    if not reasons and to_status not in ALLOWED_TRANSITIONS[from_status]:
        reasons.append(f"POLICY_TRANSITION_INVALID:{from_status}->{to_status}")
    return {
        "transition_status": "BLOCKED" if reasons else "ALLOWED",
        "from_status": from_status,
        "to_status": to_status,
        "reason_codes": sorted(set(reasons)),
        "auto_promoted": False,
        "auto_approved": False,
        "auto_activated": False,
        "auto_retired": False,
    }
