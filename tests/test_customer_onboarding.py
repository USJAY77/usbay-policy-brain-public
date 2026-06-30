from __future__ import annotations

import pytest

from governance.customer_onboarding import empty_customer_onboarding_dashboard_state, evaluate_customer_onboarding
from governance.customer_onboarding_contracts import build_customer_onboarding_record


pytestmark = pytest.mark.governance


def onboarding(**overrides):
    dependency_fields = {
        "document_library_status",
        "policy_registry_status",
        "audit_registry_status",
        "release_governance_status",
        "tenant_boundary_status",
    }
    dependency_overrides = {key: overrides.pop(key) for key in list(overrides) if key in dependency_fields}
    payload = {
        "onboarding_id": "onboard-1",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "policy_version": "policy-v1",
        "audit_linkage": "audit-1",
        "evidence_linkage": "evidence-1",
        "customer_classification": "ENTERPRISE",
        "jurisdiction": "EU",
        "risk_classification": "MEDIUM",
        "workspace_owner": "owner-1",
        "onboarding_state": "ACTIVE",
        "human_approval": True,
        "created_at": "2026-06-18T00:00:00Z",
        "governance_terms_accepted": True,
        "reason_codes": [],
        "fail_closed": False,
    }
    payload.update(overrides)
    record = build_customer_onboarding_record(**payload)
    record.update(
        {
            "document_library_status": "READY",
            "policy_registry_status": "READY",
            "audit_registry_status": "READY",
            "release_governance_status": "READY",
            "tenant_boundary_status": "READY",
        }
    )
    record.update(dependency_overrides)
    return record


def test_customer_onboarding_active_when_all_controls_pass():
    result = evaluate_customer_onboarding(
        record=onboarding(),
        known_tenant_ids=set(),
        assigned_jurisdiction="EU",
        human_approval={"approved": True},
    )

    assert result["customer_onboarding_status"] == "ACTIVE"
    assert result["pending_customer_count"] == 0
    assert result["workspace_creation_enabled"] is False
    assert result["tenant_creation_enabled"] is False


def test_customer_onboarding_blocks_duplicate_and_jurisdiction_conflict():
    result = evaluate_customer_onboarding(
        record=onboarding(jurisdiction="US"),
        known_tenant_ids={"tenant-1"},
        assigned_jurisdiction="EU",
        human_approval={"approved": True},
    )

    assert result["customer_onboarding_status"] == "BLOCKED"
    assert "DUPLICATE_TENANT_IDENTITY" in result["customer_onboarding_reason_codes"]
    assert "CONFLICTING_JURISDICTION" in result["customer_onboarding_reason_codes"]


def test_customer_onboarding_blocks_missing_dependencies():
    record = onboarding(document_library_status="BLOCKED", tenant_boundary_status="BLOCKED")
    result = evaluate_customer_onboarding(record=record, human_approval={"approved": True})

    assert "MISSING_DOCUMENT_LIBRARY" in result["customer_onboarding_reason_codes"]
    assert "MISSING_TENANT_BOUNDARY" in result["customer_onboarding_reason_codes"]


def test_empty_customer_onboarding_dashboard_state_is_fail_closed():
    state = empty_customer_onboarding_dashboard_state()

    assert state["customer_onboarding_status"] == "BLOCKED"
    assert state["workspace_creation_enabled"] is False
    assert state["tenant_creation_enabled"] is False
    assert state["auto_onboarding"] is False
    assert state["auto_approval"] is False
