from pilot_operations.end_to_end_dry_run import simulate_operator_approval


def test_known_operator_with_approval_verifies_without_execution():
    result = simulate_operator_approval("pilot-operator-usbay-governance-001")

    assert result["decision"] == "VERIFIED"
    assert result["state"] == "READ_ONLY"
    assert result["approval_required"] is True
    assert result["execution_allowed"] is False
    assert result["gaps"] == []


def test_unknown_operator_blocks():
    result = simulate_operator_approval("unknown-operator")

    assert result["decision"] == "BLOCKED"
    assert "UNKNOWN_OPERATOR" in result["gaps"]


def test_missing_operator_approval_blocks():
    result = simulate_operator_approval("pilot-operator-usbay-governance-001", approval_present=False)

    assert result["decision"] == "BLOCKED"
    assert "MISSING_OPERATOR_APPROVAL" in result["gaps"]
