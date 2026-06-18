from __future__ import annotations

from typing import Any


def evaluate_customer_commercial_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("customer_commercial_record") is not True:
        reasons.append("MISSING_CUSTOMER_COMMERCIAL_RECORD")
    if not isinstance(record, dict) or str(record.get("customer_commercial_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_CUSTOMER_ACTIVATION")
    if isinstance(record, dict) and record.get("customer_activation") is True:
        reasons.append("CUSTOMER_ACTIVATION_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"customer_commercial_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
