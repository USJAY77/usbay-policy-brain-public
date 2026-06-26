from __future__ import annotations

from runtime.computer_use.controlled_mac_execution import execution_kill_switch_contract_json, evaluate_kill_switch


def test_kill_switch_contract_disables_execution_by_default() -> None:
    contract = execution_kill_switch_contract_json()
    assert contract["default_state"] == "DISABLED_UNSAFE"
    assert contract["execution_activation_allowed"] is False
    assert contract["rollback_records_reason_and_audit_hash"] is True


def test_any_unsafe_state_disables_execution_and_records_rollback() -> None:
    result = evaluate_kill_switch(unsafe_state=True, reason="unsafe-screen")
    assert result["decision"] == "BLOCKED"
    assert result["kill_switch"] == "DISABLED_UNSAFE"
    assert result["rollback"]["reason"] == "unsafe-screen"
    assert result["rollback"]["audit_hash"]


def test_audit_unknown_screen_and_approval_failures_disable_execution() -> None:
    result = evaluate_kill_switch(audit_failure=True, unknown_screen=True, approval_failure=True)
    assert set(result["rollback"]["triggers"]) == {"AUDIT_FAILURE", "UNKNOWN_SCREEN", "APPROVAL_FAILURE"}
    assert result["execution_performed"] is False


def test_kill_switch_safe_state_does_not_execute() -> None:
    result = evaluate_kill_switch()
    assert result["decision"] == "READY_FOR_REVIEW"
    assert result["kill_switch"] == "ENABLED_SAFE"
    assert result["execution_performed"] is False
