from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


CONTROLLED_LIVE_PILOT_VERSION = "pb221-controlled-live-pilot-contract-v1"
LIMITED_WORKFLOW = ("GitHub", "USBAY Gateway", "Human Approval", "Codex")


class PilotState(str, Enum):
    BLOCKED = "BLOCKED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"


@dataclass(frozen=True)
class ControlledLivePilotContract:
    pilot_id: str
    workflow: tuple[str, ...] = LIMITED_WORKFLOW
    state: PilotState = PilotState.BLOCKED
    human_approval_required: bool = True
    live_execution_allowed: bool = False
    production_activation_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["workflow"] = list(self.workflow)
        payload["state"] = self.state.value
        payload["contract_version"] = CONTROLLED_LIVE_PILOT_VERSION
        return payload


def controlled_live_pilot_contract_json() -> dict[str, Any]:
    return ControlledLivePilotContract(pilot_id="pb221-github-usbay-approval-codex").to_dict()


def evaluate_pilot_readiness(
    *,
    credential_verified: bool = False,
    human_approved: bool = False,
    policy_hash_verified: bool = False,
    deployment_attested: bool = False,
) -> dict[str, Any]:
    gaps: list[str] = []
    if not credential_verified:
        gaps.append("CREDENTIAL_MISSING")
    if not human_approved:
        gaps.append("HUMAN_APPROVAL_REQUIRED")
    if not policy_hash_verified:
        gaps.append("POLICY_HASH_MISSING")
    if not deployment_attested:
        gaps.append("ATTESTATION_MISSING")
    return {
        "decision": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "state": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "workflow": list(LIMITED_WORKFLOW),
        "live_execution_allowed": False,
        "production_activation_allowed": False,
        "contract_version": CONTROLLED_LIVE_PILOT_VERSION,
    }
