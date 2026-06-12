from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


CONNECTOR_CONTRACT_VERSION = "pb213-connector-governance-gates-v1"


class GovernedConnectorState(str, Enum):
    DISABLED = "DISABLED"
    DRY_RUN = "DRY_RUN"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class ConnectorContract:
    name: str
    state: GovernedConnectorState = GovernedConnectorState.DISABLED
    live_activation_allowed: bool = False
    external_calls_allowed: bool = False
    requires_human_approval: bool = True
    evidence_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        data["contract_version"] = CONNECTOR_CONTRACT_VERSION
        return data


CONNECTOR_NAMES = ("LinkedIn", "Notion", "Euria", "GitHub", "Codex")


def default_connector_contracts() -> dict[str, ConnectorContract]:
    return {name: ConnectorContract(name=name) for name in CONNECTOR_NAMES}


def connector_contracts_json() -> dict[str, Any]:
    return {
        "contract_version": CONNECTOR_CONTRACT_VERSION,
        "production_activation_allowed": False,
        "external_calls_allowed": False,
        "connectors": {name: contract.to_dict() for name, contract in default_connector_contracts().items()},
    }


def transition_connector_state(
    contract: ConnectorContract,
    requested_state: GovernedConnectorState,
    *,
    human_approved: bool = False,
) -> ConnectorContract:
    if requested_state == GovernedConnectorState.DISABLED:
        return ConnectorContract(name=contract.name)
    if requested_state == GovernedConnectorState.DRY_RUN:
        return ConnectorContract(name=contract.name, state=GovernedConnectorState.DRY_RUN)
    if requested_state == GovernedConnectorState.HUMAN_APPROVAL_REQUIRED:
        return ConnectorContract(name=contract.name, state=GovernedConnectorState.HUMAN_APPROVAL_REQUIRED)
    if requested_state == GovernedConnectorState.BLOCKED:
        return ConnectorContract(name=contract.name, state=GovernedConnectorState.BLOCKED)
    return ConnectorContract(name=contract.name, state=GovernedConnectorState.BLOCKED)
