from __future__ import annotations

import pytest

from governance.workspace_access import evaluate_workspace_access


pytestmark = pytest.mark.governance


def workspace(**overrides):
    payload = {"workspace_id": "ws-1", "tenant_id": "tenant-1", "shared_default": False}
    payload.update(overrides)
    return payload


def test_workspace_access_allowed_with_matching_tenant_and_approval():
    result = evaluate_workspace_access(
        workspace=workspace(),
        requesting_tenant_id="tenant-1",
        human_approval={"approved": True},
    )

    assert result["workspace_access_status"] == "ALLOWED"
    assert result["connector_write_enabled"] is False


def test_cross_tenant_workspace_access_blocks():
    result = evaluate_workspace_access(
        workspace=workspace(tenant_id="tenant-2"),
        requesting_tenant_id="tenant-1",
        human_approval={"approved": True},
    )

    assert result["workspace_access_status"] == "BLOCKED"
    assert "CROSS_TENANT_ACCESS" in result["reason_codes"]


def test_shared_default_workspace_blocks():
    result = evaluate_workspace_access(
        workspace=workspace(shared_default=True),
        requesting_tenant_id="tenant-1",
        human_approval={"approved": True},
    )

    assert "SHARED_DEFAULT_WORKSPACE" in result["reason_codes"]


def test_no_human_approval_blocks():
    result = evaluate_workspace_access(workspace=workspace(), requesting_tenant_id="tenant-1", human_approval=None)

    assert "NO_HUMAN_APPROVAL" in result["reason_codes"]
