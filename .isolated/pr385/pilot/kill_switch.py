from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


PILOT_KILL_SWITCH_VERSION = "pb229-pilot-kill-switch-v1"
KILL_SWITCH_TRIGGERS = (
    "unsafe_state",
    "connector_failure",
    "audit_failure",
    "approval_expiry",
)


@dataclass(frozen=True)
class PilotKillSwitchContract:
    enabled: bool = True
    default_state: str = "ENABLED"
    automation_state: str = "BLOCKED"
    connector_failure_disables_pilot: bool = True
    audit_failure_disables_pilot: bool = True
    approval_expiry_disables_pilot: bool = True
    live_execution_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["contract_version"] = PILOT_KILL_SWITCH_VERSION
        payload["triggers"] = list(KILL_SWITCH_TRIGGERS)
        return payload


def pilot_kill_switch_contract_json() -> dict[str, Any]:
    return PilotKillSwitchContract().to_dict()


def evaluate_kill_switch(
    *,
    unsafe_state: bool = False,
    connector_failure: bool = False,
    audit_failure: bool = False,
    approval_expired: bool = False,
) -> dict[str, Any]:
    triggers: list[str] = []
    if unsafe_state:
        triggers.append("UNSAFE_STATE")
    if connector_failure:
        triggers.append("CONNECTOR_FAILURE")
    if audit_failure:
        triggers.append("AUDIT_FAILURE")
    if approval_expired:
        triggers.append("APPROVAL_EXPIRY")
    return {
        "decision": "BLOCKED",
        "pilot_enabled": False if triggers else False,
        "kill_switch_enabled": True,
        "automation_state": "BLOCKED",
        "triggers": triggers,
        "contract_version": PILOT_KILL_SWITCH_VERSION,
        "live_execution_allowed": False,
    }
