from __future__ import annotations

import pytest

from governance.observation_contracts import OBSERVATION_HEALTH_SCHEMA, OBSERVATION_POLICY_VERSION
from governance.runtime_observability import (
    OBSERVABLE_COMPONENTS,
    build_runtime_health_snapshot,
    empty_runtime_observation_dashboard_state,
    evaluate_component_health,
)


pytestmark = pytest.mark.governance


def health(component="Gateway", **overrides):
    payload = {
        "schema": OBSERVATION_HEALTH_SCHEMA,
        "snapshot_id": f"{component}-snapshot",
        "event_id": f"{component}-event",
        "component": component,
        "status": "HEALTHY",
        "timestamp": "2026-06-17T08:00:00Z",
        "policy_version": OBSERVATION_POLICY_VERSION,
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
        "fail_closed": False,
        "reason_codes": [],
    }
    payload.update(overrides)
    return payload


def test_all_components_healthy_when_audited_and_lined():
    inputs = {component: health(component) for component in OBSERVABLE_COMPONENTS}

    snapshot = build_runtime_health_snapshot(component_health=inputs)

    assert snapshot["runtime_health"] == "HEALTHY"
    assert snapshot["fail_closed"] is False
    assert snapshot["execution_enabled"] is False
    assert snapshot["deployment_enabled"] is False


@pytest.mark.parametrize("field", ["audit_hash", "lineage_hash"])
def test_missing_audit_or_lineage_blocks_component(field):
    state, reasons = evaluate_component_health("Gateway", health(**{field: ""}))

    assert state == "BLOCKED"
    assert reasons


def test_unknown_state_blocks():
    state, reasons = evaluate_component_health("Gateway", health(status="UNKNOWN"))

    assert state == "BLOCKED"
    assert "OBSERVATION_COMPONENT_UNKNOWN_STATE:Gateway" in reasons


def test_missing_component_health_blocks_runtime():
    snapshot = build_runtime_health_snapshot(component_health={})

    assert snapshot["runtime_health"] == "BLOCKED"
    assert snapshot["fail_closed"] is True
    assert snapshot["observation_count"] == len(OBSERVABLE_COMPONENTS)


def test_empty_dashboard_state_is_read_only_and_blocked():
    state = empty_runtime_observation_dashboard_state()

    assert state["runtime_health"] == "BLOCKED"
    assert state["event_timeline_status"] == "BLOCKED"
    assert state["drift_status"] == "BLOCKED"
    assert state["auto_healed"] is False
    assert state["auto_fixed"] is False
    assert state["auto_corrected"] is False
    assert state["auto_executed"] is False
    assert state["auto_deployed"] is False
