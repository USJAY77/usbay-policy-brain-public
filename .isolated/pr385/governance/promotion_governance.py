from __future__ import annotations

from typing import Any


def evaluate_promotion_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or str(record.get("promotion_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_PROMOTION")
    if isinstance(record, dict) and record.get("auto_promotion") is True:
        reasons.append("AUTO_PROMOTION_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"promotion_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
