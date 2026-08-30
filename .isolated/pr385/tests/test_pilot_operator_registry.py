from pilot_operations.controlled_pilot_operations import (
    pilot_operator_registry_contract_json,
    validate_pilot_operator,
)


def test_operator_registry_defaults_unknown_to_blocked():
    contract = pilot_operator_registry_contract_json()

    assert contract["default_state"] == "BLOCKED"
    assert contract["unknown_operator_outcome"] == "BLOCKED"
    assert contract["production_activation_allowed"] is False
    assert contract["external_calls_allowed"] is False


def test_unknown_operator_blocks():
    result = validate_pilot_operator("unknown-operator")

    assert result["decision"] == "BLOCKED"
    assert result["state"] == "BLOCKED"
    assert result["gaps"] == ["UNKNOWN_OPERATOR"]


def test_missing_operator_blocks():
    result = validate_pilot_operator(None)

    assert result["decision"] == "BLOCKED"
    assert result["gaps"] == ["MISSING_OPERATOR"]


def test_approved_operator_is_read_only():
    result = validate_pilot_operator("pilot-operator-usbay-governance-001")

    assert result["decision"] == "VERIFIED"
    assert result["state"] == "READ_ONLY"
    assert result["gaps"] == []
