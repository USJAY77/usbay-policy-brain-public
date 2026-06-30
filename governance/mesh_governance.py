from __future__ import annotations

from typing import Any


def evaluate_mesh_governance(mesh: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(mesh, dict):
        reasons.append("MESH_STATE_MALFORMED")
    else:
        if not str(mesh.get("mesh_node_identity", "")).strip():
            reasons.append("MESH_NODE_UNKNOWN")
        if mesh.get("mesh_quorum") != "MET":
            reasons.append("MESH_QUORUM_MISSING")
        if not str(mesh.get("mesh_lineage", "")).strip() and not str(mesh.get("lineage_hash", "")).strip():
            reasons.append("MESH_LINEAGE_BREAK")
        if not str(mesh.get("mesh_audit_continuity", "")).strip() or mesh.get("mesh_audit_continuity") == "BROKEN":
            reasons.append("MESH_AUDIT_CONTINUITY_MISSING")
    status = "READY" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.sovereign.environment.v1",
        "mesh_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status != "READY",
        "read_only": True,
        "execution_enabled": False,
        "cluster_write_enabled": False,
        "kubernetes_write_enabled": False,
        "auto_deploy": False,
        "auto_scale": False,
        "auto_update": False,
        "auto_remediate": False,
        "auto_cluster_change": False,
    }
