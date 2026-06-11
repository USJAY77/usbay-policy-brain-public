from runtime.execution_adapters.adapter_approval_binding import validate_adapter_approval_binding


def _valid_binding():
    return validate_adapter_approval_binding(
        decision_id="decision-1",
        approval_id="approval-1",
        policy_version="pb181",
        execution_token="token-1",
        authority_id="authority-1",
    )


def test_adapter_approval_binding_accepts_complete_binding() -> None:
    binding = _valid_binding()

    assert binding.decision == "ALLOW"
    assert binding.reason == "adapter_approval_binding_valid"
    assert binding.binding_hash


def test_adapter_approval_binding_fail_closed_missing_decision() -> None:
    binding = validate_adapter_approval_binding(
        decision_id=None,
        approval_id="approval-1",
        policy_version="pb181",
        execution_token="token-1",
        authority_id="authority-1",
    )

    assert binding.decision == "FAIL_CLOSED"
    assert "decision_id" in binding.reason


def test_adapter_approval_binding_fail_closed_missing_token_and_authority() -> None:
    binding = validate_adapter_approval_binding(
        decision_id="decision-1",
        approval_id="approval-1",
        policy_version="pb181",
        execution_token=None,
        authority_id=None,
    )

    assert binding.decision == "FAIL_CLOSED"
    assert "execution_token" in binding.reason
    assert "authority_id" in binding.reason

