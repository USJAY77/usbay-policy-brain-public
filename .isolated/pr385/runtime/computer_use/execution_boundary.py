from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
from uuid import uuid4


TERMINAL_STATES = {"BLOCKED", "FAIL_CLOSED", "COMPLETED"}
VALID_STATES = {"REQUESTED", "AUTHORIZED", "HUMAN_REVIEW", *TERMINAL_STATES}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_hash(parts: list[Any]) -> str:
    payload = "|".join(str(part) for part in parts)
    return sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BoundaryDecision:
    action_id: str
    state: str
    decision: str
    reason: str
    policy_version: str
    audit_hash: str
    timestamp: str


@dataclass
class ExecutionState:
    action_id: str
    action_type: str
    target: str
    policy_version: str
    required_capability: str
    state: str = "REQUESTED"
    approval_token: str | None = None
    audit_events: list[dict[str, Any]] = field(default_factory=list)


def new_action_id(prefix: str = "action") -> str:
    return f"{prefix}_{uuid4().hex}"


class ExecutionBoundary:
    """Small fail-closed boundary for runtime action authorization."""

    def evaluate(
        self,
        state: ExecutionState,
        *,
        policy_decision: str | None,
        approval_valid: bool = False,
        policy_version: str | None = None,
    ) -> BoundaryDecision:
        timestamp = utc_now()
        if state.state not in VALID_STATES:
            return self._decision(state, "FAIL_CLOSED", "invalid_execution_state", timestamp)
        if not policy_version or policy_version != state.policy_version:
            return self._decision(state, "FAIL_CLOSED", "policy_version_mismatch", timestamp)
        if policy_decision is None:
            return self._decision(state, "FAIL_CLOSED", "missing_policy_decision", timestamp)
        if policy_decision == "ALLOW":
            return self._decision(state, "ALLOW", "policy_allowed", timestamp, next_state="AUTHORIZED")
        if policy_decision == "HUMAN_REVIEW":
            if approval_valid:
                return self._decision(state, "ALLOW", "approval_valid", timestamp, next_state="AUTHORIZED")
            return self._decision(state, "HUMAN_REVIEW", "approval_required", timestamp, next_state="HUMAN_REVIEW")
        if policy_decision == "BLOCK":
            return self._decision(state, "BLOCK", "policy_blocked", timestamp, next_state="BLOCKED")
        return self._decision(state, "FAIL_CLOSED", "unsupported_policy_decision", timestamp)

    def _decision(
        self,
        state: ExecutionState,
        decision: str,
        reason: str,
        timestamp: str,
        *,
        next_state: str | None = None,
    ) -> BoundaryDecision:
        next_state = next_state or ("FAIL_CLOSED" if decision == "FAIL_CLOSED" else state.state)
        audit_hash = stable_hash(
            [state.action_id, state.action_type, state.target, decision, reason, state.policy_version, timestamp]
        )
        if next_state in VALID_STATES:
            state.state = next_state
        event = {
            "action_id": state.action_id,
            "decision": decision,
            "reason": reason,
            "state": state.state,
            "policy_version": state.policy_version,
            "audit_hash": audit_hash,
            "timestamp": timestamp,
        }
        state.audit_events.append(event)
        return BoundaryDecision(
            action_id=state.action_id,
            state=state.state,
            decision=decision,
            reason=reason,
            policy_version=state.policy_version,
            audit_hash=audit_hash,
            timestamp=timestamp,
        )

