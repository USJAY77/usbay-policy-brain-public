from __future__ import annotations

import pytest

from governance.computer_use_contracts import build_computer_use_record
from governance.computer_use_registry import ComputerUseRegistry, empty_computer_use_dashboard_state, evaluate_computer_use_governance


pytestmark = pytest.mark.governance


def record(**overrides):
    payload = {
        "agent_id": "agent-1",
        "agent_type": "OPERATOR",
        "action_id": "action-1",
        "action_type": "REVIEW",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "registered_agent": True,
        "human_approval": True,
        "policy_binding": True,
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "lineage_hash": "l" * 64,
        "policy_version": "policy-v1",
    }
    payload.update(overrides)
    return build_computer_use_record(**payload)


def test_computer_use_registry_read_only_summary():
    registry = ComputerUseRegistry([record()])

    assert registry.summary()["computer_use_registry_status"] == "VALID"
    assert registry.get_agent("agent-1")["agent_id"] == "agent-1"


def test_computer_use_governance_valid_when_all_controls_pass():
    payload = record()
    result = evaluate_computer_use_governance(
        record=payload,
        registry=ComputerUseRegistry([payload]),
        requesting_tenant_id="tenant-1",
        requesting_workspace_id="ws-1",
    )

    assert result["computer_use_status"] == "GOVERNED"
    assert result["browser_control_enabled"] is False
    assert result["application_launch_enabled"] is False


def test_computer_use_governance_blocks_cross_tenant_and_forbidden_control():
    result = evaluate_computer_use_governance(record=record(browser_control=True), requesting_tenant_id="tenant-2")

    assert result["computer_use_status"] == "BLOCKED"
    assert "CROSS_TENANT_ACTION" in result["computer_use_reason_codes"]
    assert "BROWSER_CONTROL_FORBIDDEN" in result["computer_use_reason_codes"]


def test_empty_computer_use_dashboard_state_is_fail_closed():
    state = empty_computer_use_dashboard_state()

    assert state["computer_use_status"] == "BLOCKED"
    assert state["computer_use_reason_codes"] == ["UNKNOWN_AGENT", "UNKNOWN_ACTION"]
    assert state["browser_control_enabled"] is False
    assert state["mouse_control_enabled"] is False
    assert state["keyboard_control_enabled"] is False
