from pilot_operations.controlled_pilot_operations import (
    pilot_device_registry_contract_json,
    validate_pilot_device,
)


def test_device_registry_defaults_unknown_to_blocked():
    contract = pilot_device_registry_contract_json()

    assert contract["default_state"] == "BLOCKED"
    assert contract["unknown_device_outcome"] == "BLOCKED"
    assert contract["production_activation_allowed"] is False
    assert contract["external_calls_allowed"] is False


def test_unknown_device_blocks():
    result = validate_pilot_device("unknown-device")

    assert result["decision"] == "BLOCKED"
    assert result["state"] == "BLOCKED"
    assert result["gaps"] == ["UNKNOWN_DEVICE"]


def test_missing_device_blocks():
    result = validate_pilot_device(None)

    assert result["decision"] == "BLOCKED"
    assert result["gaps"] == ["MISSING_DEVICE"]


def test_approved_device_is_read_only():
    result = validate_pilot_device("pilot-device-mac-local-001")

    assert result["decision"] == "VERIFIED"
    assert result["state"] == "READ_ONLY"
    assert result["gaps"] == []
