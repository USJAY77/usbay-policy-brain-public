from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from connectors.connector_contracts import CONNECTOR_NAMES


ACTIVATION_GOVERNANCE_VERSION = "pb222-connector-activation-governance-v1"


class PilotConnectorState(str, Enum):
    DISABLED = "DISABLED"
    DRY_RUN = "DRY_RUN"
    PILOT_APPROVED = "PILOT_APPROVED"
    LIVE_BLOCKED = "LIVE_BLOCKED"


@dataclass(frozen=True)
class ConnectorActivationRule:
    connector: str
    state: PilotConnectorState = PilotConnectorState.DISABLED
    credential_required: bool = True
    approval_required: bool = True
    policy_hash_required: bool = True
    attestation_required: bool = True
    live_activation_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.value
        payload["contract_version"] = ACTIVATION_GOVERNANCE_VERSION
        return payload


def connector_activation_governance_json() -> dict[str, Any]:
    return {
        "contract_version": ACTIVATION_GOVERNANCE_VERSION,
        "states": [state.value for state in PilotConnectorState],
        "default_state": PilotConnectorState.DISABLED.value,
        "production_activation_allowed": False,
        "connectors": {name: ConnectorActivationRule(connector=name).to_dict() for name in CONNECTOR_NAMES},
    }


def evaluate_connector_activation(
    connector: str,
    *,
    credential_present: bool = False,
    approval_present: bool = False,
    policy_hash_present: bool = False,
    attestation_present: bool = False,
) -> dict[str, Any]:
    gaps: list[str] = []
    if connector not in CONNECTOR_NAMES:
        gaps.append("UNKNOWN_CONNECTOR")
    if not credential_present:
        gaps.append("CREDENTIAL_MISSING")
    if not approval_present:
        gaps.append("APPROVAL_REQUIRED")
    if not policy_hash_present:
        gaps.append("POLICY_HASH_MISSING")
    if not attestation_present:
        gaps.append("ATTESTATION_MISSING")
    state = PilotConnectorState.PILOT_APPROVED if not gaps else PilotConnectorState.LIVE_BLOCKED
    return {
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "state": state.value,
        "gaps": sorted(set(gaps)),
        "connector": connector,
        "live_activation_allowed": False,
        "external_calls_performed": False,
        "contract_version": ACTIVATION_GOVERNANCE_VERSION,
    }
