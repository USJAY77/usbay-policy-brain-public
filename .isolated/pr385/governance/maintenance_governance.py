from __future__ import annotations

from typing import Any


def evaluate_maintenance_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("maintenance_record") is not True:
        reasons.append("MISSING_MAINTENANCE_RECORD")
    if not isinstance(record, dict) or str(record.get("maintenance_status", "")) != "GOVERNED":
        reasons.append("MISSING_MAINTENANCE_RECORD")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"maintenance_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
