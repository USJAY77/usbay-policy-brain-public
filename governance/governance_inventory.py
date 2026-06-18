from __future__ import annotations

from typing import Any

from governance.capability_manifest import CAPABILITY_MANIFEST, DEFAULT_REQUIRED_CONTROLS
from governance.control_registry import CONTROL_REGISTRY
from governance.dashboard_schema import dashboard_schema
from governance.reason_code_registry import REASON_CODE_NAMESPACES


GOVERNANCE_INVENTORY_SCHEMA = "usbay.governance.inventory.v1"


def governance_capability_inventory() -> dict[str, Any]:
    return {
        "schema": GOVERNANCE_INVENTORY_SCHEMA,
        "capabilities": [dict(capability) for capability in CAPABILITY_MANIFEST],
        "controls": [dict(control) for control in CONTROL_REGISTRY],
        "reason_code_namespaces": {namespace: list(codes) for namespace, codes in REASON_CODE_NAMESPACES.items()},
        "dashboard_schema": dashboard_schema(),
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


def governance_coverage_matrix() -> list[dict[str, Any]]:
    required = set(DEFAULT_REQUIRED_CONTROLS)
    matrix: list[dict[str, Any]] = []
    for capability in CAPABILITY_MANIFEST:
        controls = set(capability.get("controls", ()))
        missing_required = sorted(required - controls)
        matrix.append(
            {
                "capability_id": capability["capability_id"],
                "display_name": capability["display_name"],
                "controls": sorted(controls),
                "missing_required_controls": missing_required,
                "audit_required": "audit_linkage" in controls,
                "evidence_required": "evidence_linkage" in controls,
                "lineage_required": "lineage_validation" in controls,
                "human_approval_required": "human_approval" in controls,
                "tenant_required": "tenant_isolation" in controls,
                "workspace_required": "workspace_isolation" in controls,
                "dashboard_states": list(capability["dashboard_states"]),
                "reason_namespace": capability["reason_namespace"],
                "coverage_status": "COVERED" if not missing_required else "GAP",
            }
        )
    return matrix


def validate_governance_inventory() -> dict[str, Any]:
    matrix = governance_coverage_matrix()
    gaps = [row for row in matrix if row["missing_required_controls"]]
    return {
        "schema": GOVERNANCE_INVENTORY_SCHEMA,
        "valid": not gaps,
        "status": "VALID" if not gaps else "BLOCKED",
        "capability_count": len(matrix),
        "coverage_matrix": matrix,
        "gap_count": len(gaps),
        "gaps": gaps,
        "read_only": True,
    }
