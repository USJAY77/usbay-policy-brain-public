from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from runtime.computer_use.execution_boundary import BoundaryDecision, ExecutionBoundary, ExecutionState, new_action_id


@dataclass(frozen=True)
class RuntimeRequest:
    action_type: str
    target: str
    required_capability: str
    policy_version: str
    action_id: str | None = None


class RuntimeController:
    """Coordinates runtime state without performing desktop/browser actions."""

    def __init__(self, boundary: ExecutionBoundary | None = None) -> None:
        self.boundary = boundary or ExecutionBoundary()
        self._states: dict[str, ExecutionState] = {}

    def create_state(self, request: RuntimeRequest) -> ExecutionState:
        action_id = request.action_id or new_action_id()
        state = ExecutionState(
            action_id=action_id,
            action_type=request.action_type,
            target=request.target,
            policy_version=request.policy_version,
            required_capability=request.required_capability,
        )
        self._states[action_id] = state
        return state

    def get_state(self, action_id: str) -> ExecutionState | None:
        return self._states.get(action_id)

    def authorize(
        self,
        action_id: str,
        *,
        policy_decision: str | None,
        approval_valid: bool = False,
        policy_version: str | None = None,
    ) -> BoundaryDecision:
        state = self._states.get(action_id)
        if state is None:
            missing = ExecutionState(
                action_id=action_id,
                action_type="unknown",
                target="unknown",
                policy_version=policy_version or "missing",
                required_capability="unknown",
            )
            return self.boundary.evaluate(
                missing,
                policy_decision=None,
                approval_valid=False,
                policy_version=policy_version,
            )
        return self.boundary.evaluate(
            state,
            policy_decision=policy_decision,
            approval_valid=approval_valid,
            policy_version=policy_version,
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            action_id: {
                "action_type": state.action_type,
                "target": state.target,
                "policy_version": state.policy_version,
                "required_capability": state.required_capability,
                "state": state.state,
                "audit_event_count": len(state.audit_events),
            }
            for action_id, state in sorted(self._states.items())
        }

