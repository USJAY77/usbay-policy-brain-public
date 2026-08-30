from __future__ import annotations

from typing import Any


def evaluate_cluster_governance(cluster: dict[str, Any] | None, *, tenant_id: str) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(cluster, dict):
        reasons.append("CLUSTER_UNKNOWN")
    else:
        if not str(cluster.get("cluster_identity", "")).strip():
            reasons.append("CLUSTER_UNKNOWN")
        if not str(cluster.get("cluster_policy", "")).strip():
            reasons.append("CLUSTER_POLICY_MISSING")
        cluster_tenant = str(cluster.get("cluster_tenant", ""))
        if not cluster_tenant:
            reasons.append("CLUSTER_TENANT_MISSING")
        elif cluster_tenant != str(tenant_id):
            reasons.append("CLUSTER_CROSS_TENANT_BLOCKED")
        if not str(cluster.get("cluster_audit", "")).strip() and not str(cluster.get("audit_hash", "")).strip():
            reasons.append("CLUSTER_AUDIT_MISSING")
    status = "READY" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.sovereign.cluster.v1",
        "cluster_governance_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status != "READY",
        "read_only": True,
        "execution_enabled": False,
        "infrastructure_change_enabled": False,
        "cluster_write_enabled": False,
        "kubernetes_write_enabled": False,
        "auto_deploy": False,
        "auto_scale": False,
        "auto_update": False,
        "auto_remediate": False,
        "auto_cluster_change": False,
    }
