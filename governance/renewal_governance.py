from __future__ import annotations

from typing import Any


def evaluate_renewal_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("renewal_record") is not True:
        reasons.append("MISSING_RENEWAL_RECORD")
    if not isinstance(record, dict) or str(record.get("renewal_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_RENEWAL_ACTION")
    if isinstance(record, dict) and record.get("renewal_execution") is True:
        reasons.append("RENEWAL_EXECUTION_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"renewal_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
