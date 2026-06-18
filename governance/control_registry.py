from __future__ import annotations

from typing import Any


CONTROL_REGISTRY_SCHEMA = "usbay.governance.control_registry.v1"

CONTROL_REGISTRY: tuple[dict[str, Any], ...] = (
    {"control_id": "audit_linkage", "label": "Audit linkage governance", "required_by_default": True},
    {"control_id": "evidence_linkage", "label": "Evidence linkage governance", "required_by_default": True},
    {"control_id": "lineage_validation", "label": "Lineage validation governance", "required_by_default": True},
    {"control_id": "human_approval", "label": "Human approval governance", "required_by_default": False},
    {"control_id": "tenant_isolation", "label": "Tenant isolation governance", "required_by_default": True},
    {"control_id": "workspace_isolation", "label": "Workspace isolation governance", "required_by_default": True},
    {"control_id": "fail_closed", "label": "Fail-closed governance", "required_by_default": True},
    {"control_id": "read_only_dashboard", "label": "Read-only dashboard governance", "required_by_default": True},
    {"control_id": "execution_forbidden", "label": "Execution forbidden governance", "required_by_default": False},
    {"control_id": "deployment_forbidden", "label": "Deployment forbidden governance", "required_by_default": False},
    {"control_id": "connector_write_forbidden", "label": "Connector write forbidden governance", "required_by_default": False},
    {"control_id": "auto_approval_forbidden", "label": "Auto approval forbidden governance", "required_by_default": False},
    {"control_id": "auto_remediation_forbidden", "label": "Auto remediation forbidden governance", "required_by_default": False},
    {"control_id": "policy_binding", "label": "Policy binding governance", "required_by_default": False},
    {"control_id": "registration", "label": "Registry membership governance", "required_by_default": False},
)


def list_controls() -> list[dict[str, Any]]:
    return [dict(control) for control in CONTROL_REGISTRY]


def control_ids() -> tuple[str, ...]:
    return tuple(str(control["control_id"]) for control in CONTROL_REGISTRY)


def validate_control_registry() -> dict[str, Any]:
    ids = control_ids()
    duplicates = sorted({control_id for control_id in ids if ids.count(control_id) > 1})
    missing = [control for control in CONTROL_REGISTRY if not control.get("control_id") or not control.get("label")]
    return {
        "schema": CONTROL_REGISTRY_SCHEMA,
        "valid": not duplicates and not missing,
        "status": "VALID" if not duplicates and not missing else "BLOCKED",
        "control_count": len(CONTROL_REGISTRY),
        "duplicate_control_ids": duplicates,
        "missing_controls": missing,
        "read_only": True,
    }
