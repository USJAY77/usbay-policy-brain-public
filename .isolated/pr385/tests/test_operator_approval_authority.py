from pilot_operations.live_pilot_authorization import (
    evaluate_operator_approval_authority,
    operator_approval_authority_contract_json,
)


def test_operator_authority_defaults_to_blocked():
    contract = operator_approval_authority_contract_json()

    assert contract["default_state"] == "BLOCKED"
    assert contract["authority"]["unknown_operator_outcome"] == "BLOCKED"
    assert contract["activation_allowed"] is False


def test_operator_without_board_approval_blocks():
    result = evaluate_operator_approval_authority("pilot-operator-usbay-governance-001")

    assert result["decision"] == "BLOCKED"
    assert "MISSING_BOARD_OPERATOR_APPROVAL" in result["gaps"]


def test_unknown_operator_blocks_even_with_board_flag():
    result = evaluate_operator_approval_authority("unknown-operator", board_approved=True)

    assert result["decision"] == "BLOCKED"
    assert "UNKNOWN_OPERATOR" in result["gaps"]


def test_known_operator_with_board_flag_is_review_only():
    result = evaluate_operator_approval_authority("pilot-operator-usbay-governance-001", board_approved=True)

    assert result["decision"] == "READY_FOR_REVIEW"
    assert result["state"] == "BOARD_REVIEW_REQUIRED"
    assert result["activation_allowed"] is False
