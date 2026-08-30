from pilot_operations.end_to_end_dry_run import simulate_device_approval


def test_known_device_with_approval_verifies_without_execution():
    result = simulate_device_approval("pilot-device-mac-local-001")

    assert result["decision"] == "VERIFIED"
    assert result["state"] == "READ_ONLY"
    assert result["approval_required"] is True
    assert result["execution_allowed"] is False
    assert result["gaps"] == []


def test_unknown_device_blocks():
    result = simulate_device_approval("unknown-device")

    assert result["decision"] == "BLOCKED"
    assert "UNKNOWN_DEVICE" in result["gaps"]


def test_missing_device_registry_blocks():
    result = simulate_device_approval("pilot-device-mac-local-001", registry_present=False)

    assert result["decision"] == "BLOCKED"
    assert "MISSING_DEVICE_REGISTRY" in result["gaps"]


def test_missing_device_approval_blocks():
    result = simulate_device_approval("pilot-device-mac-local-001", approval_present=False)

    assert result["decision"] == "BLOCKED"
    assert "MISSING_DEVICE_APPROVAL" in result["gaps"]
