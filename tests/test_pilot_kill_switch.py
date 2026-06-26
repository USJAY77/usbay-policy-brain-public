from __future__ import annotations

from pilot.kill_switch import evaluate_kill_switch, pilot_kill_switch_contract_json


def test_pilot_kill_switch_defaults_enabled_and_blocks_automation() -> None:
    contract = pilot_kill_switch_contract_json()
    assert contract["enabled"] is True
    assert contract["default_state"] == "ENABLED"
    assert contract["automation_state"] == "BLOCKED"
    assert contract["live_execution_allowed"] is False


def test_any_unsafe_state_blocks_automation() -> None:
    result = evaluate_kill_switch(unsafe_state=True)
    assert result["decision"] == "BLOCKED"
    assert result["automation_state"] == "BLOCKED"
    assert "UNSAFE_STATE" in result["triggers"]


def test_connector_audit_and_approval_failures_disable_pilot() -> None:
    result = evaluate_kill_switch(connector_failure=True, audit_failure=True, approval_expired=True)
    assert result["decision"] == "BLOCKED"
    assert result["pilot_enabled"] is False
    assert set(result["triggers"]) == {"CONNECTOR_FAILURE", "AUDIT_FAILURE", "APPROVAL_EXPIRY"}


def test_kill_switch_never_enables_live_execution_even_without_trigger() -> None:
    result = evaluate_kill_switch()
    assert result["decision"] == "BLOCKED"
    assert result["pilot_enabled"] is False
    assert result["live_execution_allowed"] is False
