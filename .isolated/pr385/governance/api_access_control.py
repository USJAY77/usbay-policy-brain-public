from __future__ import annotations

from typing import Any


def evaluate_api_access_control(
    record: dict[str, Any] | None,
    *,
    requesting_tenant_id: str = "",
    requesting_workspace_id: str = "",
) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_API")
    else:
        if record.get("access_control_policy") is not True:
            reasons.append("MISSING_ACCESS_CONTROL")
        if requesting_tenant_id and str(record.get("tenant_id", "")) != str(requesting_tenant_id):
            reasons.append("CROSS_TENANT_API_ACCESS")
        if requesting_workspace_id and str(record.get("workspace_id", "")) != str(requesting_workspace_id):
            reasons.append("CROSS_TENANT_API_ACCESS")
        if record.get("license_entitlement") is not True:
            reasons.append("GOVERNANCE_BYPASS_ATTEMPT")
    clean = sorted(set(reasons))
    return {
        "schema": "usbay.api.access_control.v1",
        "api_access_control_status": "VALID" if not clean else "BLOCKED",
        "reason_codes": clean,
        "read_only": True,
        "auto_approval": False,
        "api_invocation_enabled": False,
    }
