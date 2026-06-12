from __future__ import annotations

from runtime_trust.pilot_activation import device_operator_attestation_contract_json, validate_device_operator_attestation


def _payload() -> dict:
    return {
        "device_id": "mac-1",
        "attestation_id": "attestation-1",
        "operator_id": "operator-1",
        "approval_id": "approval-1",
    }


def test_attestation_contract_requires_device_operator_approval_and_attestation() -> None:
    contract = device_operator_attestation_contract_json()
    assert set(contract["required_fields"]) == {"device_id", "attestation_id", "operator_id", "approval_id"}
    assert contract["production_activation_allowed"] is False


def test_unknown_device_blocks() -> None:
    result = validate_device_operator_attestation(_payload(), known_devices=set(), known_operators={"operator-1"})
    assert result["decision"] == "BLOCKED"
    assert "UNKNOWN_DEVICE" in result["gaps"]


def test_unknown_operator_blocks() -> None:
    result = validate_device_operator_attestation(_payload(), known_devices={"mac-1"}, known_operators=set())
    assert result["decision"] == "BLOCKED"
    assert "UNKNOWN_OPERATOR" in result["gaps"]


def test_missing_attestation_blocks() -> None:
    payload = _payload()
    payload["attestation_id"] = ""
    result = validate_device_operator_attestation(payload, known_devices={"mac-1"}, known_operators={"operator-1"})
    assert result["decision"] == "BLOCKED"
    assert "MISSING_ATTESTATION_ID" in result["gaps"]


def test_known_device_and_operator_verifies_without_production_activation() -> None:
    result = validate_device_operator_attestation(_payload(), known_devices={"mac-1"}, known_operators={"operator-1"})
    assert result["decision"] == "VERIFIED"
    assert result["production_activation_allowed"] is False
