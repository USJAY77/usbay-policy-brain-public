"""Local-only governed agent runtime coordinator.

The coordinator models development-agent state transitions as deterministic
metadata. It never executes actions, starts processes, calls providers, or
activates production behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any, Mapping, Sequence


READY = "READY"
RUNNING = "RUNNING"
WAITING = "WAITING"
BLOCKED = "BLOCKED"
FAILED = "FAILED"
FINISHED = "FINISHED"
STATES = frozenset({READY, RUNNING, WAITING, BLOCKED, FAILED, FINISHED})

SUPPORTED_ACTORS = frozenset({"codex", "replit", "local_terminal"})
SUPPORTED_CAPABILITIES = frozenset({"design", "local_validation", "reporting", "audit_review"})
SUPPORTED_ACTIONS = frozenset({"coordinate", "handoff", "validate", "report", "wait"})

RUNTIME_READY = "RUNTIME_READY"
RUNTIME_BLOCKED = "RUNTIME_BLOCKED"

UNKNOWN_ACTOR = "UNKNOWN_ACTOR"
UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
UNKNOWN_ACTION = "UNKNOWN_ACTION"
MISSING_GOVERNANCE_METADATA = "MISSING_GOVERNANCE_METADATA"
INVALID_STATE = "INVALID_STATE"
EXECUTION_REQUESTED = "EXECUTION_REQUESTED"
RAW_PAYLOAD_FORBIDDEN = "RAW_PAYLOAD_FORBIDDEN"

_SENSITIVE_KEYS = frozenset({
    "api_key",
    "body",
    "content",
    "credential",
    "credentials",
    "password",
    "payload",
    "private_key",
    "raw_payload",
    "secret",
    "token",
})


@dataclass(frozen=True)
class AgentRuntimeRequest:
    actor: str
    capability: str
    action: str
    state: str
    tenant_id: str
    policy_hash: str
    evidence_hash: str
    correlation_id: str
    requested_execution: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentRuntimeDecision:
    runtime_id: str
    runtime_state: str
    readiness_state: str
    actor_hash: str
    capability_hash: str
    action_hash: str
    tenant_hash: str
    policy_hash: str
    evidence_hash: str
    correlation_hash: str
    denial_reasons: tuple[str, ...]
    allowed_state_transitions: tuple[str, ...]
    execution_allowed: bool = False
    hash_only: bool = True
    redacted: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "runtime_id": self.runtime_id,
            "runtime_state": self.runtime_state,
            "readiness_state": self.readiness_state,
            "actor_hash": self.actor_hash,
            "capability_hash": self.capability_hash,
            "action_hash": self.action_hash,
            "tenant_hash": self.tenant_hash,
            "policy_hash": self.policy_hash,
            "evidence_hash": self.evidence_hash,
            "correlation_hash": self.correlation_hash,
            "denial_reasons": self.denial_reasons,
            "allowed_state_transitions": self.allowed_state_transitions,
            "execution_allowed": self.execution_allowed,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
        }


def coordinate_agent_runtime(request: AgentRuntimeRequest) -> AgentRuntimeDecision:
    """Return deterministic metadata for a governed agent coordination request."""

    actor = request.actor.strip().lower()
    capability = request.capability.strip().lower()
    action = request.action.strip().lower()
    state = request.state.strip().upper()
    reasons = tuple(sorted(set(_denial_reasons(request, actor, capability, action, state))))
    runtime_state = BLOCKED if reasons else state
    readiness_state = RUNTIME_BLOCKED if reasons else RUNTIME_READY
    payload = {
        "actor_hash": _hash_text(actor),
        "capability_hash": _hash_text(capability),
        "action_hash": _hash_text(action),
        "tenant_hash": _hash_text(request.tenant_id),
        "policy_hash": request.policy_hash,
        "evidence_hash": request.evidence_hash,
        "correlation_hash": _hash_text(request.correlation_id),
        "runtime_state": runtime_state,
        "readiness_state": readiness_state,
        "denial_reasons": reasons,
        "execution_allowed": False,
        "hash_only": True,
        "redacted": True,
    }
    return AgentRuntimeDecision(
        runtime_id=_canonical_hash(payload),
        runtime_state=runtime_state,
        readiness_state=readiness_state,
        actor_hash=_hash_text(actor),
        capability_hash=_hash_text(capability),
        action_hash=_hash_text(action),
        tenant_hash=_hash_text(request.tenant_id),
        policy_hash=request.policy_hash,
        evidence_hash=request.evidence_hash,
        correlation_hash=_hash_text(request.correlation_id),
        denial_reasons=reasons,
        allowed_state_transitions=_allowed_transitions(runtime_state),
    )


def _denial_reasons(
    request: AgentRuntimeRequest,
    actor: str,
    capability: str,
    action: str,
    state: str,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if actor not in SUPPORTED_ACTORS:
        reasons.append(UNKNOWN_ACTOR)
    if capability not in SUPPORTED_CAPABILITIES:
        reasons.append(UNKNOWN_CAPABILITY)
    if action not in SUPPORTED_ACTIONS:
        reasons.append(UNKNOWN_ACTION)
    if state not in STATES:
        reasons.append(INVALID_STATE)
    if not all((request.tenant_id, request.policy_hash, request.evidence_hash, request.correlation_id)):
        reasons.append(MISSING_GOVERNANCE_METADATA)
    if request.requested_execution:
        reasons.append(EXECUTION_REQUESTED)
    if _contains_raw_payload(request.metadata):
        reasons.append(RAW_PAYLOAD_FORBIDDEN)
    return tuple(reasons)


def _allowed_transitions(state: str) -> tuple[str, ...]:
    transitions = {
        READY: (RUNNING, WAITING, BLOCKED),
        RUNNING: (WAITING, FINISHED, FAILED, BLOCKED),
        WAITING: (RUNNING, BLOCKED),
        BLOCKED: (),
        FAILED: (),
        FINISHED: (),
    }
    return transitions.get(state, ())


def _contains_raw_payload(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).lower() in _SENSITIVE_KEYS or _contains_raw_payload(child) for key, child in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_raw_payload(item) for item in value)
    return False


def _hash_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()
