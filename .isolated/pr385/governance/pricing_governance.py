from __future__ import annotations

from typing import Any


def evaluate_pricing_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("pricing_record") is not True:
        reasons.append("MISSING_PRICING_RECORD")
    if not isinstance(record, dict) or str(record.get("pricing_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_PRICING_ACTION")
    if isinstance(record, dict) and record.get("pricing_modification") is True:
        reasons.append("PRICING_MODIFICATION_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"pricing_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
