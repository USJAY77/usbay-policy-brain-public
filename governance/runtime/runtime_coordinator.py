"""Metadata-only governed runtime integration coordinator.

This module connects the local design-only runtime components into one
deterministic pipeline. It never starts tmux, spawns subprocesses, opens
sockets, calls providers, or enables production execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping, Sequence


READY = "READY"
WAITING = "WAITING"
BLOCKED = "BLOCKED"
FAILED = "FAILED"
FINISHED = "FINISHED"
SCHEDULER_STATES = frozenset({READY, WAITING, BLOCKED, FAILED, FINISHED})
HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
UNKNOWN = "UNKNOWN"
COMPONENT_STATES = frozenset({READY, WAITING, BLOCKED, FAILED, FINISHED, HEALTHY, DEGRADED, UNKNOWN})
SUPPORTED_ACTORS = frozenset({"codex", "replit", "local_terminal"})

ROUTE_VALIDATE = "validate"
ROUTE_PUBLISH = "publish"
ROUTE_SUBSCRIBE = "subscribe"
ROUTE_AUDIT = "audit"
ROUTE_FAIL_CLOSED = "fail_closed"
EVENT_ROUTES = frozenset({ROUTE_VALIDATE, ROUTE_PUBLISH, ROUTE_SUBSCRIBE, ROUTE_AUDIT, ROUTE_FAIL_CLOSED})

COORDINATOR_READY = "COORDINATOR_READY"
COORDINATOR_BLOCKED = "COORDINATOR_BLOCKED"
COORDINATOR_STATES = frozenset({COORDINATOR_READY, COORDINATOR_BLOCKED})

UNKNOWN_ACTOR = "UNKNOWN_ACTOR"
UNKNOWN_RUNTIME = "UNKNOWN_RUNTIME"
MISSING_EVIDENCE = "MISSING_EVIDENCE"
MISSING_DECISION_METADATA = "MISSING_DECISION_METADATA"
INVALID_STATE = "INVALID_STATE"
RUNTIME_UNAVAILABLE = "RUNTIME_UNAVAILABLE"
UNKNOWN_EVENT_ROUTE = "UNKNOWN_EVENT_ROUTE"
EXECUTION_REQUESTED = "EXECUTION_REQUESTED"
PROVIDER_EXECUTION_REQUESTED = "PROVIDER_EXECUTION_REQUESTED"
PRODUCTION_ACTIVATION_REQUESTED = "PRODUCTION_ACTIVATION_REQUESTED"
RAW_PAYLOAD_FORBIDDEN = "RAW_PAYLOAD_FORBIDDEN"
MISSING_GOVERNANCE_METADATA = "MISSING_GOVERNANCE_METADATA"

_SENSITIVE_KEYS = frozenset({
    "api_key",
    "body",
    "content",
    "credential",
    "credentials",
    "password",
    "payload",
    "private_key",
    "prompt",
    "prompts",
    "provider_data",
    "raw_payload",
    "secret",
    "sensitive",
    "sensitive_value",
    "token",
})


@dataclass(frozen=True)
class RuntimeComponentReference:
    name: str
    state: str
    evidence_hash: str
    available: bool = True


@dataclass(frozen=True)
class RuntimeCoordinatorRequest:
    runtime_id: str
    actor: str
    tenant_id: str
    policy_hash: str
    orchestration_hash: str
    evidence_hash: str
    health_hash: str
    decision_metadata_hash: str
    timestamp: str
    coordinator_state: str
    scheduler_state: str
    event_route: str
    agent_runtime: RuntimeComponentReference
    scheduler: RuntimeComponentReference
    event_bus: RuntimeComponentReference
    runtime_health: RuntimeComponentReference
    tmux: RuntimeComponentReference
    gateway: RuntimeComponentReference
    audit: RuntimeComponentReference
    requested_execution: bool = False
    provider_execution_requested: bool = False
    production_activation_requested: bool = False
    metadata: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class RuntimeCoordinatorDecision:
    runtime_id: str
    coordinator_state: str
    actor_hash: str
    scheduler_contract_state: str
    event_route: str
    policy_hash: str
    orchestration_hash: str
    health_hash: str
    decision_metadata_hash: str
    timestamp: str
    decision_hash: str
    runtime_evidence_hash: str
    component_hashes: Mapping[str, str]
    health_aggregation_hash: str
    blocking_reasons: tuple[str, ...]
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    hash_only: bool = True
    redacted: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "runtime_id": self.runtime_id,
            "coordinator_state": self.coordinator_state,
            "actor_hash": self.actor_hash,
            "scheduler_contract_state": self.scheduler_contract_state,
            "event_route": self.event_route,
            "policy_hash": self.policy_hash,
            "orchestration_hash": self.orchestration_hash,
            "health_hash": self.health_hash,
            "decision_metadata_hash": self.decision_metadata_hash,
            "timestamp": self.timestamp,
            "decision_hash": self.decision_hash,
            "runtime_evidence_hash": self.runtime_evidence_hash,
            "component_hashes": dict(self.component_hashes),
            "health_aggregation_hash": self.health_aggregation_hash,
            "blocking_reasons": self.blocking_reasons,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
        }


def coordinate_runtime(request: RuntimeCoordinatorRequest) -> RuntimeCoordinatorDecision:
    """Integrate runtime metadata into one fail-closed coordinator decision."""

    actor = request.actor.strip().lower()
    requested_coordinator_state = request.coordinator_state.strip().upper()
    scheduler_state = request.scheduler_state.strip().upper()
    event_route = request.event_route.strip().lower()
    components = _components(request)
    blocking_reasons = tuple(sorted(set(_blocking_reasons(
        request,
        actor,
        requested_coordinator_state,
        scheduler_state,
        event_route,
        components,
    ))))
    coordinator_state = COORDINATOR_BLOCKED if blocking_reasons else COORDINATOR_READY
    component_hashes = {component.name: _component_hash(component) for component in components}
    health_aggregation = {
        "scheduler": component_hashes.get("scheduler", _hash_text("missing:scheduler")),
        "coordinator": _hash_text(coordinator_state),
        "audit": component_hashes.get("audit", _hash_text("missing:audit")),
        "tmux": component_hashes.get("tmux", _hash_text("missing:tmux")),
        "gateway": component_hashes.get("gateway", _hash_text("missing:gateway")),
    }
    evidence_payload = {
        "runtime_id_hash": _hash_text(request.runtime_id),
        "actor_hash": _hash_text(actor),
        "policy_hash": request.policy_hash,
        "orchestration_hash": request.orchestration_hash,
        "health_hash": request.health_hash,
        "decision_metadata_hash": request.decision_metadata_hash,
        "timestamp_hash": _hash_text(request.timestamp),
        "component_hashes": component_hashes,
        "health_aggregation_hash": _canonical_hash(health_aggregation),
        "requested_coordinator_state": requested_coordinator_state if requested_coordinator_state in COORDINATOR_STATES else COORDINATOR_BLOCKED,
        "scheduler_contract_state": scheduler_state if scheduler_state in SCHEDULER_STATES else BLOCKED,
        "event_route_hash": _hash_text(event_route),
        "blocking_reasons": blocking_reasons,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "hash_only": True,
        "redacted": True,
    }
    decision_hash = _canonical_hash(evidence_payload)
    return RuntimeCoordinatorDecision(
        runtime_id=request.runtime_id,
        coordinator_state=coordinator_state,
        actor_hash=_hash_text(actor),
        scheduler_contract_state=scheduler_state if scheduler_state in SCHEDULER_STATES else BLOCKED,
        event_route=event_route if event_route in EVENT_ROUTES else ROUTE_FAIL_CLOSED,
        policy_hash=request.policy_hash,
        orchestration_hash=request.orchestration_hash,
        health_hash=request.health_hash,
        decision_metadata_hash=request.decision_metadata_hash,
        timestamp=request.timestamp,
        decision_hash=decision_hash,
        runtime_evidence_hash=_canonical_hash({"runtime_evidence": decision_hash}),
        component_hashes=component_hashes,
        health_aggregation_hash=evidence_payload["health_aggregation_hash"],
        blocking_reasons=blocking_reasons,
    )


def _blocking_reasons(
    request: RuntimeCoordinatorRequest,
    actor: str,
    requested_coordinator_state: str,
    scheduler_state: str,
    event_route: str,
    components: Sequence[RuntimeComponentReference],
) -> tuple[str, ...]:
    reasons: list[str] = []
    if actor not in SUPPORTED_ACTORS:
        reasons.append(UNKNOWN_ACTOR)
    if requested_coordinator_state not in COORDINATOR_STATES:
        reasons.append(INVALID_STATE)
    if not all((request.runtime_id, request.tenant_id, request.policy_hash, request.orchestration_hash, request.evidence_hash, request.health_hash, request.timestamp)):
        reasons.append(MISSING_GOVERNANCE_METADATA)
    if not request.decision_metadata_hash:
        reasons.append(MISSING_DECISION_METADATA)
    if scheduler_state not in SCHEDULER_STATES:
        reasons.append(INVALID_STATE)
    if event_route not in EVENT_ROUTES:
        reasons.append(UNKNOWN_EVENT_ROUTE)
    if request.requested_execution:
        reasons.append(EXECUTION_REQUESTED)
    if request.provider_execution_requested:
        reasons.append(PROVIDER_EXECUTION_REQUESTED)
    if request.production_activation_requested:
        reasons.append(PRODUCTION_ACTIVATION_REQUESTED)
    if _contains_raw_payload(request.metadata or {}):
        reasons.append(RAW_PAYLOAD_FORBIDDEN)

    expected_names = {"agent_runtime", "scheduler", "event_bus", "runtime_health", "tmux", "gateway", "audit"}
    component_names = {component.name for component in components}
    if component_names != expected_names:
        reasons.append(UNKNOWN_RUNTIME)
    for component in components:
        if component.name not in expected_names:
            reasons.append(UNKNOWN_RUNTIME)
        if not component.evidence_hash:
            reasons.append(MISSING_EVIDENCE)
        if component.state.upper() not in COMPONENT_STATES:
            reasons.append(INVALID_STATE)
        if not component.available or component.state.upper() in {BLOCKED, FAILED, UNKNOWN}:
            reasons.append(RUNTIME_UNAVAILABLE)
    return tuple(reasons)


def _components(request: RuntimeCoordinatorRequest) -> tuple[RuntimeComponentReference, ...]:
    return (
        request.agent_runtime,
        request.scheduler,
        request.event_bus,
        request.runtime_health,
        request.tmux,
        request.gateway,
        request.audit,
    )


def _component_hash(component: RuntimeComponentReference) -> str:
    return _canonical_hash({
        "name_hash": _hash_text(component.name),
        "state_hash": _hash_text(component.state.upper()),
        "evidence_hash": component.evidence_hash,
        "available": component.available,
    })
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
