from __future__ import annotations

from typing import Any

from governance.customer_workspace_contracts import ALLOWED_WORKSPACE_STATES


def evaluate_workspace_lifecycle(workspace: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    state = ""
    if not isinstance(workspace, dict):
        reasons.append("UNKNOWN_WORKSPACE")
    else:
        state = str(workspace.get("workspace_state", ""))
        if state not in ALLOWED_WORKSPACE_STATES:
            reasons.append(f"WORKSPACE_STATE_UNKNOWN:{state or 'MISSING'}")
        if workspace.get("human_approval") is not True and state in {"APPROVED", "ACTIVE"}:
            reasons.append("NO_HUMAN_APPROVAL")
        if workspace.get("auto_onboarding") is True:
            reasons.append("AUTO_ONBOARDING_FORBIDDEN")
        if workspace.get("auto_activation") is True:
            reasons.append("AUTO_ACTIVATION_FORBIDDEN")
        if workspace.get("auto_archive") is True:
            reasons.append("AUTO_ARCHIVE_FORBIDDEN")
    status = "VALID" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.customer.workspace_lifecycle.v1",
        "workspace_lifecycle_status": status,
        "workspace_state": state or "BLOCKED",
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status != "VALID",
        "read_only": True,
        "onboarding_enabled": False,
        "activation_enabled": False,
        "archive_enabled": False,
        "auto_onboarding": False,
        "auto_activation": False,
        "auto_archive": False,
        "auto_approval": False,
    }
