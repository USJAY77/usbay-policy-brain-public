from __future__ import annotations

from typing import Any


def evaluate_billing_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("billing_record") is not True:
        reasons.append("MISSING_BILLING_RECORD")
    if not isinstance(record, dict) or str(record.get("billing_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_BILLING_ACTION")
    if isinstance(record, dict) and record.get("billing_execution") is True:
        reasons.append("BILLING_EXECUTION_FORBIDDEN")
    if isinstance(record, dict) and record.get("payment_processing") is True:
        reasons.append("PAYMENT_PROCESSING_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"billing_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
