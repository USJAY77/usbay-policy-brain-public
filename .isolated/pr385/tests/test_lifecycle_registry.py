from __future__ import annotations

import pytest

from governance.lifecycle_contracts import LIFECYCLE_GOVERNANCE_POLICY_VERSION, build_lifecycle_record, compute_lifecycle_governance_hash
from governance.lifecycle_registry import LifecycleRegistry, empty_lifecycle_dashboard_state


pytestmark = pytest.mark.governance


def lifecycle_record(**overrides):
    payload = build_lifecycle_record(
        change_id="change-1",
        tenant_id="tenant-1",
        workspace_id="workspace-1",
        change_request=True,
        registered_change=True,
        release_approval=True,
        runtime_approval=True,
        rollback_approval=True,
        incident_record=True,
        maintenance_record=True,
        policy_binding=True,
        audit_hash="a" * 64,
        evidence_hash="e" * 64,
        lineage_hash="l" * 64,
        change_status="GOVERNED",
        release_status="AUTHORIZED",
        promotion_status="AUTHORIZED",
        runtime_status="AUTHORIZED",
        rollback_status="AUTHORIZED",
        incident_status="AUTHORIZED",
        maintenance_status="GOVERNED",
        policy_version=LIFECYCLE_GOVERNANCE_POLICY_VERSION,
    )
    payload.update(overrides)
    if "lifecycle_governance_hash" not in overrides:
        payload["lifecycle_governance_hash"] = compute_lifecycle_governance_hash(payload)
    return payload


def test_lifecycle_registry_lists_records_read_only():
    registry = LifecycleRegistry([lifecycle_record()])

    assert registry.get_change("change-1")["change_status"] == "GOVERNED"
    assert registry.list_changes()[0]["change_id"] == "change-1"
    assert registry.summary()["lifecycle_registry_status"] == "VALID"
    assert registry.summary()["deployment_enabled"] is False
    assert registry.summary()["runtime_modification_enabled"] is False


def test_empty_lifecycle_registry_blocks_unknown_change():
    summary = LifecycleRegistry().summary()

    assert summary["lifecycle_registry_status"] == "BLOCKED"
    assert summary["lifecycle_reason_codes"] == ["UNKNOWN_CHANGE"]


def test_empty_lifecycle_dashboard_state_blocks_execution():
    state = empty_lifecycle_dashboard_state()

    assert state["lifecycle_status"] == "BLOCKED"
    assert state["change_status"] == "BLOCKED"
    assert state["release_status"] == "BLOCKED"
    assert state["promotion_status"] == "BLOCKED"
    assert state["runtime_status"] == "BLOCKED"
    assert state["rollback_status"] == "BLOCKED"
    assert state["incident_status"] == "BLOCKED"
    assert state["maintenance_status"] == "BLOCKED"
    assert state["lifecycle_reason_codes"] == ["UNKNOWN_CHANGE"]
    assert state["execution_enabled"] is False
    assert state["deployment_enabled"] is False
    assert state["runtime_modification_enabled"] is False
    assert state["policy_modification_enabled"] is False
    assert state["connector_write_enabled"] is False
    assert state["auto_release"] is False
    assert state["auto_promotion"] is False
    assert state["auto_remediation"] is False
    assert state["auto_rollback"] is False
    assert state["auto_approval"] is False
