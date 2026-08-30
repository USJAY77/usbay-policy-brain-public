from __future__ import annotations

from runtime.computer_use.controlled_mac_execution import (
    human_approved_desktop_actions_contract_json,
    validate_desktop_action_approval,
)


def _approval(action_id: str = "a1") -> dict:
    return {
        "approval_id": "approval-1",
        "action_id": action_id,
        "approval_status": "APPROVED",
        "expires_at": "2030-01-01T00:00:00Z",
    }


def test_human_approved_actions_contract_allows_only_future_action_set() -> None:
    contract = human_approved_desktop_actions_contract_json()
    assert set(contract["allowed_future_actions"]) == {"click", "type_text", "press_key", "scroll", "open_app"}
    assert contract["approval_id_required"] is True
    assert contract["free_form_execution_allowed"] is False


def test_missing_approval_blocks() -> None:
    result = validate_desktop_action_approval(action_id="a1", action_type="click", approval=None)
    assert result["decision"] == "BLOCKED"
    assert "MISSING_APPROVAL" in result["gaps"]


def test_expired_reused_and_mismatched_approval_blocks() -> None:
    approval = _approval(action_id="other")
    approval["expires_at"] = "2026-01-01T00:00:00Z"
    result = validate_desktop_action_approval(
        action_id="a1",
        action_type="click",
        approval=approval,
        used_approval_ids={"approval-1"},
        now="2026-06-11T00:00:00Z",
    )
    assert result["decision"] == "BLOCKED"
    assert "APPROVAL_EXPIRED" in result["gaps"]
    assert "APPROVAL_REUSED" in result["gaps"]
    assert "APPROVAL_ACTION_MISMATCH" in result["gaps"]


def test_valid_approval_verifies_without_execution() -> None:
    result = validate_desktop_action_approval(
        action_id="a1",
        action_type="click",
        approval=_approval(),
        now="2026-06-11T00:00:00Z",
    )
    assert result["decision"] == "VERIFIED"
    assert result["execution_performed"] is False
