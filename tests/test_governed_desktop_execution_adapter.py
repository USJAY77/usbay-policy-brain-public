from __future__ import annotations

from runtime.computer_use.vision_governance import propose_desktop_action


def test_desktop_adapter_proposes_action_with_required_fields() -> None:
    action = propose_desktop_action(action_id="action-1", action_type="click", screen_class="GITHUB_PR")
    for field in (
        "action_id",
        "screen_class",
        "risk_level",
        "policy_hash",
        "approval_required",
        "decision",
        "audit_hash",
    ):
        assert field in action
    assert action["live_execution_allowed"] is False
    assert action["pyautogui_execution_allowed"] is False


def test_desktop_adapter_blocks_low_risk_action_by_default() -> None:
    action = propose_desktop_action(action_id="action-2", action_type="scroll", screen_class="SAFE_WORKSPACE")
    assert action["decision"] == "BLOCKED"
    assert action["approval_required"] is True


def test_desktop_adapter_blocks_critical_action() -> None:
    action = propose_desktop_action(
        action_id="action-3",
        action_type="type_text",
        screen_class="PAYMENT_SCREEN",
        sensitive_markers=["payment"],
    )
    assert action["decision"] == "BLOCKED"
    assert action["risk_level"] == "CRITICAL"


def test_desktop_adapter_unknown_action_blocks() -> None:
    action = propose_desktop_action(action_id="action-4", action_type="drag", screen_class="CODE_EDITOR")
    assert action["decision"] == "BLOCKED"
