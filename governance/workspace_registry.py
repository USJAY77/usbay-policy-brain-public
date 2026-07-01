from __future__ import annotations

from typing import Any

from governance.customer_workspace_contracts import validate_customer_workspace


class WorkspaceRegistry:
    def __init__(self, workspaces: list[dict[str, Any]] | None = None):
        self._workspaces = tuple(workspace for workspace in workspaces or [] if isinstance(workspace, dict))

    def get_workspace(self, workspace_id: str) -> list[dict[str, Any]]:
        return [dict(workspace) for workspace in self._workspaces if workspace.get("workspace_id") == workspace_id]

    def list_workspaces(self) -> list[dict[str, Any]]:
        return [dict(workspace) for workspace in self._workspaces]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        for workspace in self._workspaces:
            validation = validate_customer_workspace(workspace)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
        status = "VALID" if self._workspaces and not reasons else "BLOCKED"
        return {
            "workspace_registry_status": status,
            "workspace_count": len(self._workspaces),
            "workspace_reason_codes": sorted(set(reasons)) or ([] if self._workspaces else ["UNKNOWN_WORKSPACE"]),
            "read_only": True,
            "create_enabled": False,
            "update_enabled": False,
            "delete_enabled": False,
            "auto_onboarding": False,
            "auto_activation": False,
            "auto_archive": False,
        }


def evaluate_workspace_registry(workspaces: list[dict[str, Any]] | None) -> dict[str, Any]:
    if not isinstance(workspaces, list):
        return WorkspaceRegistry().summary()
    return WorkspaceRegistry(workspaces).summary()
