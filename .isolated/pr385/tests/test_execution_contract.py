from runtime.computer_use.execution_contract import create_contract


def test_execution_contract_allow_path() -> None:
    contract = create_contract(
        decision_id="decision-1",
        audit_hash_value="audit",
        policy_version="pb169",
        action_type="read_screen",
        target="screen",
        status="ALLOW",
    )

    assert contract.status == "ALLOW"
    assert contract.current_hash


def test_execution_contract_missing_fields_fail_closed() -> None:
    contract = create_contract(
        decision_id=None,
        audit_hash_value="audit",
        policy_version="pb169",
        action_type="read_screen",
        target="screen",
        status="ALLOW",
    )

    assert contract.status == "FAIL_CLOSED"


def test_execution_contract_unsupported_action_blocks() -> None:
    contract = create_contract(
        decision_id="decision-1",
        audit_hash_value="audit",
        policy_version="pb169",
        action_type="launch_missiles",
        target="screen",
        status="ALLOW",
    )

    assert contract.status == "BLOCK"

