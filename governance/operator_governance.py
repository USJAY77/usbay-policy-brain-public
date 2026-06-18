from __future__ import annotations

from typing import Any


def evaluate_operator_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_AGENT")
    else:
        if record.get("agent_type") != "OPERATOR":
            return {"operator_status": "NOT_APPLICABLE", "reason_codes": [], "read_only": True, "auto_approval": False}
        if record.get("human_approval") is not True:
            reasons.append("MISSING_APPROVAL")
        if record.get("auto_approval") is True:
            reasons.append("AUTO_APPROVAL_FORBIDDEN")
    clean = sorted(set(reasons))
    return {"operator_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True, "auto_approval": False}
