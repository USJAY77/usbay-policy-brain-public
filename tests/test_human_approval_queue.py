from __future__ import annotations

from datetime import datetime, timedelta, timezone

from approval.human_approval_queue import HumanApprovalQueue, approval_queue_contract_json


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _past() -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def test_non_read_action_requires_explicit_human_approval() -> None:
    queue = HumanApprovalQueue()
    result = queue.require_approval(
        action_id="publish-linkedin-dry-run",
        action_type="write",
        actor="automation-readiness",
        target="LinkedIn",
        risk_level="HIGH",
        policy_hash="e" * 64,
        expires_at=_future(),
    )
    assert result["decision"] == "PENDING_HUMAN_APPROVAL"
    assert result["approval"]["status"] == "PENDING"
    assert queue.evaluate_action("publish-linkedin-dry-run")["decision"] == "FAIL_CLOSED"
    assert queue.approve("publish-linkedin-dry-run", human_actor="human-reviewer")["decision"] == "APPROVED"
    assert queue.evaluate_action("publish-linkedin-dry-run")["decision"] == "APPROVED"


def test_expired_approval_fails_closed() -> None:
    queue = HumanApprovalQueue()
    result = queue.require_approval(
        action_id="expired-write",
        action_type="write",
        actor="automation-readiness",
        target="GitHub",
        risk_level="HIGH",
        policy_hash="e" * 64,
        expires_at=_past(),
    )
    assert result["decision"] == "FAIL_CLOSED"
    assert "APPROVAL_EXPIRED" in result["gaps"]


def test_sensitive_data_is_rejected_from_approval_records() -> None:
    queue = HumanApprovalQueue()
    result = queue.require_approval(
        action_id="publish-with-token",
        action_type="write",
        actor="automation-readiness",
        target="GitHub token=secret",
        risk_level="HIGH",
        policy_hash="e" * 64,
        expires_at=_future(),
    )
    assert result["decision"] == "FAIL_CLOSED"
    assert "SENSITIVE_DATA_NOT_ALLOWED" in result["gaps"]


def test_contract_declares_required_fields_and_fail_closed_expiry() -> None:
    contract = approval_queue_contract_json()
    assert contract["expired_approvals_fail_closed"] is True
    assert "action_id" in contract["required_fields"]
    assert "status" in contract["required_fields"]
