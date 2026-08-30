from __future__ import annotations

import pytest

from governance.action_governance import evaluate_action_governance


pytestmark = pytest.mark.governance


def test_action_governance_valid_for_same_tenant_workspace():
    result = evaluate_action_governance(
        {"action_type": "REVIEW", "tenant_id": "tenant-1", "workspace_id": "ws-1"},
        requesting_tenant_id="tenant-1",
        requesting_workspace_id="ws-1",
    )

    assert result["action_status"] == "VALID"
    assert result["auto_remediation"] is False


def test_action_governance_blocks_unknown_cross_tenant_and_auto_remediation():
    result = evaluate_action_governance(
        {"action_type": "CLICK", "tenant_id": "tenant-1", "workspace_id": "ws-1", "auto_remediation": True},
        requesting_tenant_id="tenant-2",
        requesting_workspace_id="ws-2",
    )

    assert "UNKNOWN_ACTION" in result["reason_codes"]
    assert "CROSS_TENANT_ACTION" in result["reason_codes"]
    assert "AUTO_REMEDIATION_FORBIDDEN" in result["reason_codes"]
