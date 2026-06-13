from runtime.computer_use.approval_workflow import ApprovalWorkflow


def test_approval_lifecycle_valid_once() -> None:
    workflow = ApprovalWorkflow()
    record = workflow.request("action-1", "merge requires review")
    workflow.approve(record.token, "approved by human")

    valid, reason = workflow.validate(record.token, "action-1")
    replay_valid, replay_reason = workflow.validate(record.token, "action-1")

    assert valid is True
    assert reason == "approval_valid"
    assert replay_valid is False
    assert replay_reason == "approval_replay"


def test_denied_approval_blocks() -> None:
    workflow = ApprovalWorkflow()
    record = workflow.request("action-2", "dangerous")
    workflow.deny(record.token, "not allowed")

    valid, reason = workflow.validate(record.token, "action-2")

    assert valid is False
    assert reason == "approval_not_granted"


def test_expired_approval_blocks() -> None:
    workflow = ApprovalWorkflow()
    record = workflow.request("action-3", "short", ttl_seconds=-1)
    workflow.approve(record.token, "too late")

    valid, reason = workflow.validate(record.token, "action-3")

    assert valid is False
    assert reason == "approval_expired"

