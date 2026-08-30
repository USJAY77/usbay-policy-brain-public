from __future__ import annotations

from runtime.computer_use.mac_dry_run_loop import (
    create_human_approval_request,
    evaluate_approval_for_execution,
    propose_dry_run_action,
)


def _action() -> dict:
    return propose_dry_run_action(action_id="approval-action", action_type="click", screen_metadata={"title": "GitHub pull request"})


def test_human_approval_request_created_for_proposed_action() -> None:
    approval = create_human_approval_request(_action(), expires_at="2030-01-01T00:00:00Z")
    assert approval["action_id"] == "approval-action"
    assert approval["approval_status"] == "PENDING"
    assert approval["real_execution_allowed"] is False


def test_missing_approval_fails_closed() -> None:
    result = evaluate_approval_for_execution(None)
    assert result["decision"] == "FAIL_CLOSED"
    assert "MISSING_APPROVAL" in result["gaps"]
    assert result["real_execution_performed"] is False


def test_expired_approval_fails_closed() -> None:
    approval = create_human_approval_request(_action(), expires_at="2026-01-01T00:00:00Z")
    approval["approval_status"] = "APPROVED"
    result = evaluate_approval_for_execution(approval, now="2026-06-11T00:00:00Z")
    assert result["decision"] == "FAIL_CLOSED"
    assert "APPROVAL_EXPIRED" in result["gaps"]


def test_approved_unexpired_request_verifies_without_execution() -> None:
    approval = create_human_approval_request(_action(), expires_at="2030-01-01T00:00:00Z")
    approval["approval_status"] = "APPROVED"
    result = evaluate_approval_for_execution(approval, now="2026-06-11T00:00:00Z")
    assert result["decision"] == "VERIFIED"
    assert result["real_execution_performed"] is False
    assert result["desktop_control_allowed"] is False
