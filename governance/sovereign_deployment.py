from __future__ import annotations

from typing import Any

from governance.sovereign_deployment_contracts import validate_sovereign_deployment


def _ready(result: dict[str, Any] | None, status_key: str) -> bool:
    return isinstance(result, dict) and result.get(status_key) == "READY" and result.get("fail_closed") is False


def evaluate_sovereign_deployment(
    *,
    deployment_record: dict[str, Any] | None,
    node_governance: dict[str, Any] | None,
    cluster_governance: dict[str, Any] | None,
    airgap_governance: dict[str, Any] | None,
    mesh_governance: dict[str, Any] | None,
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_sovereign_deployment(deployment_record)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("SOVEREIGN_DEPLOYMENT_CONTRACT_INVALID",))
    if not _ready(node_governance, "node_governance_status"):
        reasons.extend((node_governance or {}).get("reason_codes", []) if isinstance(node_governance, dict) else [])
        reasons.append("SOVEREIGN_NODE_NOT_READY")
    if not _ready(cluster_governance, "cluster_governance_status"):
        reasons.extend((cluster_governance or {}).get("reason_codes", []) if isinstance(cluster_governance, dict) else [])
        reasons.append("SOVEREIGN_CLUSTER_NOT_READY")
    if not _ready(airgap_governance, "airgap_status"):
        reasons.extend((airgap_governance or {}).get("reason_codes", []) if isinstance(airgap_governance, dict) else [])
        reasons.append("SOVEREIGN_AIRGAP_NOT_READY")
    if not _ready(mesh_governance, "mesh_status"):
        reasons.extend((mesh_governance or {}).get("reason_codes", []) if isinstance(mesh_governance, dict) else [])
        reasons.append("SOVEREIGN_MESH_NOT_READY")
    status = "READY" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.sovereign.deployment.v1",
        "sovereign_deployment_status": status,
        "node_governance_status": (node_governance or {}).get("node_governance_status", "BLOCKED")
        if isinstance(node_governance, dict)
        else "BLOCKED",
        "cluster_governance_status": (cluster_governance or {}).get("cluster_governance_status", "BLOCKED")
        if isinstance(cluster_governance, dict)
        else "BLOCKED",
        "airgap_status": (airgap_governance or {}).get("airgap_status", "BLOCKED")
        if isinstance(airgap_governance, dict)
        else "BLOCKED",
        "mesh_status": (mesh_governance or {}).get("mesh_status", "BLOCKED")
        if isinstance(mesh_governance, dict)
        else "BLOCKED",
        "sovereignty_level": str((deployment_record or {}).get("sovereignty_level", "UNKNOWN"))
        if isinstance(deployment_record, dict)
        else "UNKNOWN",
        "reason_codes": sorted(set(str(reason) for reason in reasons if reason)),
        "fail_closed": status != "READY",
        "read_only": True,
        "deployment_enabled": False,
        "execution_enabled": False,
        "infrastructure_change_enabled": False,
        "shell_control_enabled": False,
        "cluster_write_enabled": False,
        "kubernetes_write_enabled": False,
        "auto_deploy": False,
        "auto_scale": False,
        "auto_update": False,
        "auto_remediate": False,
        "auto_cluster_change": False,
    }


def empty_sovereign_deployment_dashboard_state() -> dict[str, Any]:
    return {
        "sovereign_deployment_status": "BLOCKED",
        "node_governance_status": "BLOCKED",
        "cluster_governance_status": "BLOCKED",
        "airgap_status": "BLOCKED",
        "mesh_status": "BLOCKED",
        "sovereignty_level": "UNKNOWN",
        "reason_codes": ["SOVEREIGN_DEPLOYMENT_NOT_EVALUATED"],
        "fail_closed": True,
        "read_only": True,
        "deployment_enabled": False,
        "execution_enabled": False,
        "infrastructure_change_enabled": False,
        "shell_control_enabled": False,
        "cluster_write_enabled": False,
        "kubernetes_write_enabled": False,
        "auto_deploy": False,
        "auto_scale": False,
        "auto_update": False,
        "auto_remediate": False,
        "auto_cluster_change": False,
    }
