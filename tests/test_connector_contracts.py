from __future__ import annotations

from connectors.connector_contracts import (
    CONNECTOR_NAMES,
    GovernedConnectorState,
    connector_contracts_json,
    default_connector_contracts,
    transition_connector_state,
)


def test_all_required_connectors_default_to_disabled() -> None:
    contracts = default_connector_contracts()
    assert set(contracts) == set(CONNECTOR_NAMES)
    assert all(contract.state == GovernedConnectorState.DISABLED for contract in contracts.values())
    assert all(contract.live_activation_allowed is False for contract in contracts.values())


def test_connector_contract_export_disallows_external_calls() -> None:
    exported = connector_contracts_json()
    assert exported["production_activation_allowed"] is False
    assert exported["external_calls_allowed"] is False
    assert exported["connectors"]["LinkedIn"]["state"] == "DISABLED"


def test_transition_never_enables_live_activation() -> None:
    contract = default_connector_contracts()["GitHub"]
    transitioned = transition_connector_state(contract, GovernedConnectorState.DRY_RUN)
    assert transitioned.state == GovernedConnectorState.DRY_RUN
    assert transitioned.live_activation_allowed is False
    assert transitioned.external_calls_allowed is False
