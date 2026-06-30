from __future__ import annotations

from typing import Any


def evaluate_browser_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_ACTION")
    elif record.get("browser_control") is True:
        reasons.append("BROWSER_CONTROL_FORBIDDEN")
    clean = sorted(set(reasons))
    return {"browser_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True, "browser_control_enabled": False}
