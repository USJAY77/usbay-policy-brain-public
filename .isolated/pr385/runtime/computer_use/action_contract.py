from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


REQUIRED_DECISION_INPUTS = {
    "action_type",
    "target",
    "screen_summary",
    "provider_response",
    "approval_state",
    "policy_version",
}


@dataclass(frozen=True)
class ComputerUseActionContract:
    action_type: str
    target: str
    screen_summary: str
    provider_response: dict[str, Any]
    approval_state: str
    policy_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_action_contract(payload: dict[str, Any]) -> ComputerUseActionContract:
    if not isinstance(payload, dict):
        raise ValueError("ACTION_CONTRACT_MUST_BE_OBJECT")
    missing = sorted(field for field in REQUIRED_DECISION_INPUTS if field not in payload)
    if missing:
        raise ValueError("ACTION_CONTRACT_REQUIRED_INPUT_MISSING:" + ",".join(missing))
    provider_response = payload["provider_response"]
    if not isinstance(provider_response, dict):
        raise ValueError("PROVIDER_RESPONSE_MUST_BE_OBJECT")
    return ComputerUseActionContract(
        action_type=str(payload["action_type"]),
        target=str(payload["target"]),
        screen_summary=str(payload["screen_summary"]),
        provider_response=provider_response,
        approval_state=str(payload["approval_state"]),
        policy_version=str(payload["policy_version"]),
    )
