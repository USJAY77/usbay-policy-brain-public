from __future__ import annotations

import pytest

from governance.customer_workspace import empty_customer_workspace_dashboard_state, evaluate_customer_workspace
from governance.customer_workspace_contracts import build_customer_workspace
from governance.workspace_registry import WorkspaceRegistry


pytestmark = pytest.mark.governance


def workspace(**overrides):
    payload = {
        "workspace_id": "ws-1",
        "workspace_name": "Customer One",
        "tenant_id": "tenant-1",
        "workspace_state": "ACTIVE",
        "policy_hash": "p" * 64,
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "lineage_hash": "l" * 64,
        "human_approval": True,
        "created_at": "2026-06-18T00:00:00Z",
        "reason_codes": [],
        "fail_closed": False,
    }
    payload.update(overrides)
    return build_customer_workspace(**payload)


def test_customer_workspace_active_when_all_controls_pass():
    record = workspace()
    result = evaluate_customer_workspace(
        workspace=record,
        registry=WorkspaceRegistry([record]),
        requesting_tenant_id="tenant-1",
        human_approval={"approved": True},
    )

    assert result["customer_workspace_status"] == "ACTIVE"
    assert result["workspace_count"] == 1
    assert result["billing_write_enabled"] is False
    assert result["document_publish_enabled"] is False


def test_customer_workspace_blocks_missing_evidence():
    record = workspace(evidence_hash="")
    result = evaluate_customer_workspace(
        workspace=record,
        registry=WorkspaceRegistry([record]),
        requesting_tenant_id="tenant-1",
        human_approval={"approved": True},
    )

    assert result["customer_workspace_status"] == "BLOCKED"
    assert "MISSING_EVIDENCE" in result["workspace_reason_codes"]


def test_customer_workspace_blocks_cross_tenant_access():
    record = workspace()
    result = evaluate_customer_workspace(
        workspace=record,
        registry=WorkspaceRegistry([record]),
        requesting_tenant_id="tenant-2",
        human_approval={"approved": True},
    )

    assert "CROSS_TENANT_ACCESS" in result["workspace_reason_codes"]


def test_empty_customer_workspace_dashboard_state_is_fail_closed():
    state = empty_customer_workspace_dashboard_state()

    assert state["customer_workspace_status"] == "BLOCKED"
    assert state["workspace_count"] == 0
    assert state["connector_write_enabled"] is False
    assert state["auto_onboarding"] is False
    assert state["auto_approval"] is False
