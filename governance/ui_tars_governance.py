from __future__ import annotations

from typing import Any


def evaluate_ui_tars_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_AGENT")
    else:
        if record.get("agent_type") != "UI_TARS":
            return {
                "ui_tars_status": "NOT_APPLICABLE",
                "reason_codes": [],
                "read_only": True,
                "mouse_control_enabled": False,
                "keyboard_control_enabled": False,
            }
        if record.get("registered_agent") is not True:
            reasons.append("UNREGISTERED_AGENT")
        if record.get("mouse_control") is True:
            reasons.append("MOUSE_CONTROL_FORBIDDEN")
        if record.get("keyboard_control") is True:
            reasons.append("KEYBOARD_CONTROL_FORBIDDEN")
    clean = sorted(set(reasons))
    return {"ui_tars_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True, "mouse_control_enabled": False, "keyboard_control_enabled": False}
