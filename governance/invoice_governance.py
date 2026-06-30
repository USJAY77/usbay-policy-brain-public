from __future__ import annotations

from typing import Any


def evaluate_invoice_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("invoice_record") is not True:
        reasons.append("MISSING_INVOICE_RECORD")
    if not isinstance(record, dict) or str(record.get("invoice_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_INVOICE_ACTION")
    if isinstance(record, dict) and record.get("invoice_sending") is True:
        reasons.append("INVOICE_SENDING_FORBIDDEN")
    if isinstance(record, dict) and record.get("email_sending") is True:
        reasons.append("EMAIL_SENDING_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"invoice_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
