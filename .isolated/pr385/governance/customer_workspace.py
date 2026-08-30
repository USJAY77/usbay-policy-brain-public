from __future__ import annotations

from typing import Any

from governance.customer_workspace_contracts import validate_customer_workspace
from governance.workspace_access import evaluate_workspace_access
from governance.workspace_lifecycle import evaluate_workspace_lifecycle
from governance.workspace_registry import WorkspaceRegistry


def evaluate_customer_workspace(
    *,
    workspace: dict[str, Any] | None,
    registry: WorkspaceRegistry | None = None,
    requesting_tenant_id: str = "",
    human_approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_customer_workspace(workspace)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("UNKNOWN_WORKSPACE",))
    workspaces = registry.list_workspaces() if isinstance(registry, WorkspaceRegistry) else ([workspace] if isinstance(workspace, dict) else [])
    registry_summary = WorkspaceRegistry(workspaces).summary()
    access = evaluate_workspace_access(
        workspace=workspace,
        requesting_tenant_id=requesting_tenant_id,
        human_approval=human_approval,
    )
    lifecycle = evaluate_workspace_lifecycle(workspace)
    if registry_summary["workspace_registry_status"] != "VALID":
        reasons.extend(registry_summary["workspace_reason_codes"])
    if access["workspace_access_status"] != "ALLOWED":
        reasons.extend(access["reason_codes"])
    if lifecycle["workspace_lifecycle_status"] != "VALID":
        reasons.extend(lifecycle["reason_codes"])
    status = "ACTIVE" if not reasons and validation.status == "ACTIVE" else ("APPROVED" if not reasons else "BLOCKED")
    return {
        "schema": "usbay.customer.workspace.v1",
        "customer_workspace_status": status,
        "workspace_count": registry_summary["workspace_count"],
        "workspace_tenant_status": "VALID" if "MISSING_TENANT" not in reasons and "CROSS_TENANT_ACCESS" not in reasons else "BLOCKED",
        "workspace_access_status": access["workspace_access_status"],
        "workspace_lifecycle_status": lifecycle["workspace_lifecycle_status"],
        "workspace_reason_codes": sorted(set(str(reason) for reason in reasons if reason)),
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "connector_write_enabled": False,
        "document_rewrite_enabled": False,
        "document_publish_enabled": False,
        "document_delete_enabled": False,
        "billing_write_enabled": False,
        "subscription_write_enabled": False,
        "auto_onboarding": False,
        "auto_activation": False,
        "auto_archive": False,
        "auto_approval": False,
    }


def empty_customer_workspace_dashboard_state() -> dict[str, Any]:
    return {
        "customer_workspace_status": "BLOCKED",
        "workspace_count": 0,
        "workspace_tenant_status": "BLOCKED",
        "workspace_access_status": "BLOCKED",
        "workspace_lifecycle_status": "BLOCKED",
        "workspace_reason_codes": ["UNKNOWN_WORKSPACE"],
        "fail_closed": True,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "connector_write_enabled": False,
        "document_rewrite_enabled": False,
        "document_publish_enabled": False,
        "document_delete_enabled": False,
        "billing_write_enabled": False,
        "subscription_write_enabled": False,
        "auto_onboarding": False,
        "auto_activation": False,
        "auto_archive": False,
        "auto_approval": False,
    }
