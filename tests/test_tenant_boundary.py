from __future__ import annotations

import pytest

from governance.tenant_boundary import (
    empty_tenant_boundary_dashboard_state,
    evaluate_audit_boundary,
    evaluate_cross_tenant_request,
    evaluate_document_boundary,
    evaluate_evidence_boundary,
    evaluate_policy_boundary,
    evaluate_release_boundary,
    evaluate_tenant_identity,
)
from governance.tenant_boundary_contracts import build_tenant_identity


pytestmark = pytest.mark.governance


def tenant(**overrides):
    payload = {
        "tenant_id": "tenant-1",
        "tenant_name": "Tenant One",
        "tenant_region": "EU",
        "tenant_classification": "ENTERPRISE",
        "policy_namespace": "tenant-1/policy",
        "evidence_namespace": "tenant-1/evidence",
        "audit_namespace": "tenant-1/audit",
        "release_namespace": "tenant-1/release",
        "document_namespace": "tenant-1/document",
        "requested_by": "human-1",
        "created_at": "2026-06-18T08:00:00Z",
        "policy_hash": "p" * 64,
        "audit_hash": "a" * 64,
    }
    payload.update(overrides)
    return build_tenant_identity(**payload)


def test_valid_identity_requires_review():
    result = evaluate_tenant_identity(tenant())

    assert result["decision"] == "REVIEW_REQUIRED"
    assert result["copy_enabled"] is False


def test_unknown_tenant_blocks():
    result = evaluate_tenant_identity(None)

    assert result["decision"] == "BLOCKED"
    assert "TENANT_IDENTITY_MALFORMED" in result["reason_codes"]


@pytest.mark.parametrize(
    ("fn", "namespace"),
    [
        (evaluate_policy_boundary, "other/policy"),
        (evaluate_evidence_boundary, "other/evidence"),
        (evaluate_audit_boundary, "other/audit"),
        (evaluate_release_boundary, "other/release"),
        (evaluate_document_boundary, "other/document"),
    ],
)
def test_namespace_mismatch_blocks(fn, namespace):
    result = fn(tenant(), namespace=namespace)

    assert result["decision"] == "BLOCKED"
    assert "BLOCKED_WITH_MISSING_NAMESPACE" in result["reason_codes"]


def test_cross_tenant_request_blocks():
    result = evaluate_cross_tenant_request(source_tenant_id="tenant-1", target_tenant_id="tenant-2", namespace="tenant-2/policy")

    assert result["decision"] == "BLOCKED"
    assert "TENANT_CROSS_TENANT_ACCESS_BLOCKED" in result["reason_codes"]


def test_missing_human_approval_for_boundary_change_blocks():
    result = evaluate_cross_tenant_request(source_tenant_id="tenant-1", target_tenant_id="tenant-1", namespace="tenant-1/policy")

    assert result["decision"] == "BLOCKED"
    assert "TENANT_BOUNDARY_CHANGE_APPROVAL_MISSING" in result["reason_codes"]


def test_empty_dashboard_blocks_and_disables_auto_tenant_actions():
    state = empty_tenant_boundary_dashboard_state()

    assert state["tenant_boundary_status"] == "BLOCKED"
    assert state["cross_tenant_access_status"] == "BLOCKED"
    assert state["auto_tenant_provisioned"] is False
    assert state["auto_tenant_migrated"] is False
    assert state["auto_tenant_shared"] is False
    assert state["auto_tenant_merged"] is False
    assert state["global_tenant_access"] is False
