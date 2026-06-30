from __future__ import annotations

from typing import Any


def evaluate_change_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.extend(["UNKNOWN_CHANGE", "MISSING_CHANGE_REQUEST"])
    else:
        if not str(record.get("change_id", "")).strip():
            reasons.append("UNKNOWN_CHANGE")
        if record.get("registered_change") is not True:
            reasons.append("UNREGISTERED_CHANGE")
        if record.get("change_request") is not True or str(record.get("change_status", "")) != "GOVERNED":
            reasons.append("MISSING_CHANGE_REQUEST")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"change_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
