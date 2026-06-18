from __future__ import annotations

import pytest

from governance.customer_readiness import evaluate_customer_readiness


pytestmark = pytest.mark.governance


def readiness(**overrides):
    payload = {
        "document_library_status": "READY",
        "policy_registry_status": "READY",
        "audit_registry_status": "READY",
        "release_governance_status": "READY",
        "tenant_boundary_status": "READY",
        "audit_linkage": "audit-1",
        "evidence_linkage": "evidence-1",
    }
    payload.update(overrides)
    return payload


def test_valid_customer_readiness():
    result = evaluate_customer_readiness(readiness())

    assert result["customer_readiness_status"] == "READY_FOR_APPROVAL"
    assert result["connector_write_enabled"] is False


def test_missing_governance_dependencies_block():
    result = evaluate_customer_readiness(
        readiness(
            document_library_status="BLOCKED",
            policy_registry_status="BLOCKED",
            audit_registry_status="BLOCKED",
            release_governance_status="BLOCKED",
            tenant_boundary_status="BLOCKED",
        )
    )

    assert "MISSING_DOCUMENT_LIBRARY" in result["reason_codes"]
    assert "MISSING_POLICY_REGISTRY" in result["reason_codes"]
    assert "MISSING_AUDIT_REGISTRY" in result["reason_codes"]
    assert "MISSING_RELEASE_GOVERNANCE" in result["reason_codes"]
    assert "MISSING_TENANT_BOUNDARY" in result["reason_codes"]


def test_missing_audit_and_evidence_linkage_block():
    result = evaluate_customer_readiness(readiness(audit_linkage="", evidence_linkage=""))

    assert "MISSING_AUDIT_LINKAGE" in result["reason_codes"]
    assert "MISSING_EVIDENCE_LINKAGE" in result["reason_codes"]
