from __future__ import annotations

from typing import Any

from governance.computer_use_contracts import SUPPORTED_ACTIONS


def evaluate_action_governance(
    record: dict[str, Any] | None,
    *,
    requesting_tenant_id: str = "",
    requesting_workspace_id: str = "",
) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_ACTION")
    else:
        if str(record.get("action_type", "")) not in SUPPORTED_ACTIONS:
            reasons.append("UNKNOWN_ACTION")
        if requesting_tenant_id and str(record.get("tenant_id", "")) != str(requesting_tenant_id):
            reasons.append("CROSS_TENANT_ACTION")
        if requesting_workspace_id and str(record.get("workspace_id", "")) != str(requesting_workspace_id):
            reasons.append("CROSS_TENANT_ACTION")
        if record.get("auto_remediation") is True:
            reasons.append("AUTO_REMEDIATION_FORBIDDEN")
    clean = sorted(set(reasons))
    return {"action_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True, "auto_remediation": False}
