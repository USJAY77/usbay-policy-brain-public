from __future__ import annotations

from typing import Any


def evaluate_node_governance(node: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(node, dict):
        reasons.append("NODE_UNKNOWN")
    else:
        if not str(node.get("node_identity", "")).strip():
            reasons.append("NODE_UNKNOWN")
        if node.get("node_trust") not in {"TRUSTED", "ATTESTED"}:
            reasons.append("NODE_UNTRUSTED")
        if not str(node.get("node_attestation", "")).strip():
            reasons.append("NODE_ATTESTATION_MISSING")
        if not str(node.get("node_lineage", "")).strip() and not str(node.get("lineage_hash", "")).strip():
            reasons.append("NODE_LINEAGE_MISSING")
        if not str(node.get("node_policy_hash", "")).strip():
            reasons.append("NODE_POLICY_HASH_MISSING")
        if not str(node.get("node_audit_hash", "")).strip():
            reasons.append("NODE_AUDIT_HASH_MISSING")
    status = "READY" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.sovereign.node.v1",
        "node_governance_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status != "READY",
        "read_only": True,
        "execution_enabled": False,
        "shell_control_enabled": False,
        "cluster_write_enabled": False,
        "kubernetes_write_enabled": False,
        "auto_deploy": False,
        "auto_scale": False,
        "auto_update": False,
        "auto_remediate": False,
        "auto_cluster_change": False,
    }
