from __future__ import annotations

import pytest

from governance.cluster_governance import evaluate_cluster_governance


pytestmark = pytest.mark.governance


def cluster(**overrides):
    payload = {
        "cluster_identity": "cluster-1",
        "cluster_policy": "policy-hash",
        "cluster_tenant": "tenant-1",
        "cluster_audit": "audit-hash",
    }
    payload.update(overrides)
    return payload


def test_valid_cluster_governance():
    result = evaluate_cluster_governance(cluster(), tenant_id="tenant-1")

    assert result["cluster_governance_status"] == "READY"
    assert result["kubernetes_write_enabled"] is False


def test_unknown_cluster_blocks():
    result = evaluate_cluster_governance(cluster(cluster_identity=""), tenant_id="tenant-1")

    assert "CLUSTER_UNKNOWN" in result["reason_codes"]


def test_cross_tenant_deployment_blocks():
    result = evaluate_cluster_governance(cluster(cluster_tenant="tenant-2"), tenant_id="tenant-1")

    assert result["cluster_governance_status"] == "BLOCKED"
    assert "CLUSTER_CROSS_TENANT_BLOCKED" in result["reason_codes"]


def test_missing_audit_blocks():
    result = evaluate_cluster_governance(cluster(cluster_audit="", audit_hash=""), tenant_id="tenant-1")

    assert "CLUSTER_AUDIT_MISSING" in result["reason_codes"]


def test_missing_policy_blocks():
    result = evaluate_cluster_governance(cluster(cluster_policy=""), tenant_id="tenant-1")

    assert "CLUSTER_POLICY_MISSING" in result["reason_codes"]
