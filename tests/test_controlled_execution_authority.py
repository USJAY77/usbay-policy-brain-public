from __future__ import annotations

from runtime.computer_use.controlled_mac_execution import (
    controlled_execution_authority_contract_json,
    evaluate_execution_authority,
)


def test_execution_authority_defaults_blocked() -> None:
    contract = controlled_execution_authority_contract_json()
    assert contract["default_state"] == "BLOCKED"
    assert contract["execution_activation_allowed"] is False


def test_execution_authority_ready_only_when_all_controls_pass() -> None:
    result = evaluate_execution_authority(
        policy_decision="ALLOW",
        human_approval="APPROVED",
        risk_level="LOW",
        screen_class="CODE_EDITOR",
        sensitive_screen=False,
        kill_switch="ENABLED_SAFE",
    )
    assert result["decision"] == "READY_FOR_REVIEW"
    assert result["execution_performed"] is False


def test_execution_authority_blocks_unknown_sensitive_and_critical() -> None:
    result = evaluate_execution_authority(
        policy_decision="ALLOW",
        human_approval="APPROVED",
        risk_level="CRITICAL",
        screen_class="UNKNOWN",
        sensitive_screen=True,
        kill_switch="ENABLED_SAFE",
    )
    assert result["decision"] == "BLOCKED"
    assert "CRITICAL_RISK_BLOCKED" in result["gaps"]
    assert "UNKNOWN_SCREEN_BLOCKED" in result["gaps"]
    assert "SENSITIVE_SCREEN_BLOCKED" in result["gaps"]


def test_high_risk_requires_approval_and_is_not_executable() -> None:
    result = evaluate_execution_authority(
        policy_decision="ALLOW",
        human_approval="APPROVED",
        risk_level="HIGH",
        screen_class="GITHUB_PR",
        sensitive_screen=False,
        kill_switch="ENABLED_SAFE",
    )
    assert result["decision"] == "BLOCKED"
    assert "HIGH_RISK_REQUIRES_APPROVAL" in result["gaps"]
