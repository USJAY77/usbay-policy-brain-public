from pilot_operations.live_pilot_authorization import (
    device_approval_authority_contract_json,
    evaluate_device_approval_authority,
)


def test_device_authority_defaults_to_blocked():
    contract = device_approval_authority_contract_json()

    assert contract["default_state"] == "BLOCKED"
    assert contract["authority"]["unknown_device_outcome"] == "BLOCKED"
    assert contract["activation_allowed"] is False


def test_device_without_board_approval_blocks():
    result = evaluate_device_approval_authority("pilot-device-mac-local-001")

    assert result["decision"] == "BLOCKED"
    assert "MISSING_BOARD_DEVICE_APPROVAL" in result["gaps"]


def test_unknown_device_blocks_even_with_board_flag():
    result = evaluate_device_approval_authority("unknown-device", board_approved=True)

    assert result["decision"] == "BLOCKED"
    assert "UNKNOWN_DEVICE" in result["gaps"]


def test_known_device_with_board_flag_is_review_only():
    result = evaluate_device_approval_authority("pilot-device-mac-local-001", board_approved=True)

    assert result["decision"] == "READY_FOR_REVIEW"
    assert result["state"] == "BOARD_REVIEW_REQUIRED"
    assert result["activation_allowed"] is False
