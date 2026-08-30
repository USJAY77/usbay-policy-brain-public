from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


ORCHESTRATOR_STATE_MODEL_VERSION = "pb334-orchestrator-state-model-v1"


class OrchestratorState(str, Enum):
    IDLE = "IDLE"
    DETECTED_FAILURE = "DETECTED_FAILURE"
    CLASSIFIED = "CLASSIFIED"
    PB_CREATED = "PB_CREATED"
    BRANCH_CREATED = "BRANCH_CREATED"
    PATCH_PROPOSED = "PATCH_PROPOSED"
    VALIDATION_RUNNING = "VALIDATION_RUNNING"
    VALIDATION_PASSED = "VALIDATION_PASSED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    MERGE_ELIGIBLE = "MERGE_ELIGIBLE"
    BLOCKED = "BLOCKED"


ALLOWED_TRANSITIONS: dict[OrchestratorState, tuple[OrchestratorState, ...]] = {
    OrchestratorState.IDLE: (OrchestratorState.DETECTED_FAILURE,),
    OrchestratorState.DETECTED_FAILURE: (OrchestratorState.CLASSIFIED, OrchestratorState.BLOCKED),
    OrchestratorState.CLASSIFIED: (OrchestratorState.PB_CREATED, OrchestratorState.BLOCKED),
    OrchestratorState.PB_CREATED: (OrchestratorState.BRANCH_CREATED, OrchestratorState.BLOCKED),
    OrchestratorState.BRANCH_CREATED: (OrchestratorState.PATCH_PROPOSED, OrchestratorState.BLOCKED),
    OrchestratorState.PATCH_PROPOSED: (OrchestratorState.VALIDATION_RUNNING, OrchestratorState.BLOCKED),
    OrchestratorState.VALIDATION_RUNNING: (
        OrchestratorState.VALIDATION_PASSED,
        OrchestratorState.VALIDATION_FAILED,
        OrchestratorState.BLOCKED,
    ),
    OrchestratorState.VALIDATION_PASSED: (OrchestratorState.HUMAN_REVIEW_REQUIRED,),
    OrchestratorState.VALIDATION_FAILED: (OrchestratorState.BLOCKED,),
    OrchestratorState.HUMAN_REVIEW_REQUIRED: (OrchestratorState.MERGE_ELIGIBLE, OrchestratorState.BLOCKED),
    OrchestratorState.MERGE_ELIGIBLE: (),
    OrchestratorState.BLOCKED: (),
}


@dataclass(frozen=True)
class StateTransitionDecision:
    decision: str
    from_state: str
    to_state: str
    reason: str
    policy_version: str = ORCHESTRATOR_STATE_MODEL_VERSION

    def to_dict(self) -> dict[str, str]:
        return {
            "decision": self.decision,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "reason": self.reason,
            "policy_version": self.policy_version,
        }


def state_model_contract() -> dict[str, Any]:
    return {
        "policy_version": ORCHESTRATOR_STATE_MODEL_VERSION,
        "states": [state.value for state in OrchestratorState],
        "terminal_states": [OrchestratorState.MERGE_ELIGIBLE.value, OrchestratorState.BLOCKED.value],
        "fail_closed_state": OrchestratorState.BLOCKED.value,
        "allowed_transitions": {
            state.value: [target.value for target in targets] for state, targets in ALLOWED_TRANSITIONS.items()
        },
    }


def evaluate_transition(from_state: str, to_state: str) -> StateTransitionDecision:
    try:
        current = OrchestratorState(from_state)
        target = OrchestratorState(to_state)
    except ValueError:
        return StateTransitionDecision(
            decision=OrchestratorState.BLOCKED.value,
            from_state=from_state,
            to_state=to_state,
            reason="UNKNOWN_ORCHESTRATOR_STATE",
        )

    if target in ALLOWED_TRANSITIONS[current]:
        return StateTransitionDecision(
            decision="ALLOW",
            from_state=current.value,
            to_state=target.value,
            reason="TRANSITION_ALLOWED",
        )

    return StateTransitionDecision(
        decision=OrchestratorState.BLOCKED.value,
        from_state=current.value,
        to_state=target.value,
        reason="TRANSITION_NOT_ALLOWED",
    )
