from __future__ import annotations

from typing import Any


def evaluate_rollback_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("rollback_approval") is not True:
        reasons.append("MISSING_ROLLBACK_APPROVAL")
    if not isinstance(record, dict) or str(record.get("rollback_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_ROLLBACK")
    if isinstance(record, dict) and record.get("auto_rollback") is True:
        reasons.append("AUTO_ROLLBACK_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"rollback_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
