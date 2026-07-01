from __future__ import annotations

from connectors.activation_governance import connector_activation_governance_json, evaluate_connector_activation
from connectors.connector_contracts import CONNECTOR_NAMES


def test_connector_activation_governance_defines_all_required_connectors_disabled() -> None:
    contract = connector_activation_governance_json()
    assert set(contract["connectors"]) == set(CONNECTOR_NAMES)
    assert contract["default_state"] == "DISABLED"
    assert all(item["state"] == "DISABLED" for item in contract["connectors"].values())


def test_connector_activation_fails_closed_when_evidence_missing() -> None:
    result = evaluate_connector_activation("GitHub")
    assert result["decision"] == "FAIL_CLOSED"
    assert result["state"] == "LIVE_BLOCKED"
    assert set(result["gaps"]) == {
        "APPROVAL_REQUIRED",
        "ATTESTATION_MISSING",
        "CREDENTIAL_MISSING",
        "POLICY_HASH_MISSING",
    }


def test_connector_activation_never_activates_even_when_pilot_ready() -> None:
    result = evaluate_connector_activation(
        "Codex",
        credential_present=True,
        approval_present=True,
        policy_hash_present=True,
        attestation_present=True,
    )
    assert result["decision"] == "VERIFIED"
    assert result["state"] == "PILOT_APPROVED"
    assert result["live_activation_allowed"] is False
    assert result["external_calls_performed"] is False
