from __future__ import annotations

from typing import Any


def evaluate_desktop_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_ACTION")
    else:
        if record.get("application_control") is True:
            reasons.append("APPLICATION_CONTROL_FORBIDDEN")
        if record.get("file_modification") is True:
            reasons.append("FILE_MODIFICATION_FORBIDDEN")
        if record.get("shell_control") is True:
            reasons.append("SHELL_CONTROL_FORBIDDEN")
    clean = sorted(set(reasons))
    return {
        "desktop_status": "VALID" if not clean else "BLOCKED",
        "reason_codes": clean,
        "read_only": True,
        "application_launch_enabled": False,
        "file_modification_enabled": False,
        "shell_control_enabled": False,
    }
