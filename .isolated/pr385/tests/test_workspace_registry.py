from __future__ import annotations

import pytest

from governance.customer_workspace_contracts import build_customer_workspace
from governance.workspace_registry import WorkspaceRegistry, evaluate_workspace_registry


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


def test_registry_counts_valid_workspaces():
    result = WorkspaceRegistry([workspace()]).summary()

    assert result["workspace_registry_status"] == "VALID"
    assert result["workspace_count"] == 1
    assert result["auto_onboarding"] is False


def test_unknown_customer_workspace_blocks():
    result = evaluate_workspace_registry(None)

    assert result["workspace_registry_status"] == "BLOCKED"
    assert "UNKNOWN_WORKSPACE" in result["workspace_reason_codes"]


def test_registry_blocks_invalid_workspace():
    result = WorkspaceRegistry([workspace(tenant_id="")]).summary()

    assert result["workspace_registry_status"] == "BLOCKED"
    assert "MISSING_TENANT" in result["workspace_reason_codes"]
