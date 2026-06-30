from __future__ import annotations

from typing import Any


def evaluate_subscription_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("subscription_record") is not True:
        reasons.append("MISSING_SUBSCRIPTION_RECORD")
    if not isinstance(record, dict) or str(record.get("subscription_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_SUBSCRIPTION_ACTION")
    if isinstance(record, dict) and record.get("subscription_activation") is True:
        reasons.append("SUBSCRIPTION_ACTIVATION_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"subscription_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
