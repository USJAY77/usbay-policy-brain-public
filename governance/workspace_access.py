from __future__ import annotations

from typing import Any


def evaluate_workspace_access(
    *,
    workspace: dict[str, Any] | None,
    requesting_tenant_id: str,
    human_approval: dict[str, Any] | None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(workspace, dict) or not str(workspace.get("workspace_id", "")).strip():
        reasons.append("UNKNOWN_WORKSPACE")
    else:
        tenant_id = str(workspace.get("tenant_id", ""))
        if not tenant_id:
            reasons.append("MISSING_TENANT")
        elif tenant_id != str(requesting_tenant_id):
            reasons.append("CROSS_TENANT_ACCESS")
        if workspace.get("shared_default") is True or str(workspace.get("workspace_id", "")).lower() in {"default", "shared"}:
            reasons.append("SHARED_DEFAULT_WORKSPACE")
    if not isinstance(human_approval, dict) or human_approval.get("approved") is not True:
        reasons.append("NO_HUMAN_APPROVAL")
    status = "ALLOWED" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.customer.workspace_access.v1",
        "workspace_access_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status != "ALLOWED",
        "read_only": True,
        "execution_enabled": False,
        "connector_write_enabled": False,
        "document_rewrite_enabled": False,
        "document_publish_enabled": False,
        "document_delete_enabled": False,
        "billing_write_enabled": False,
        "auto_approval": False,
    }
