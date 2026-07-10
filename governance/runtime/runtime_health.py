"""Deterministic runtime health metadata model.

Health checks are represented as local metadata only. The model does not start
daemons, poll, open sockets, inspect live processes, or execute tmux.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping


HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"

POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
AUDIT_NOT_READY = "AUDIT_NOT_READY"
TMUX_UNKNOWN = "TMUX_UNKNOWN"
SCHEDULER_NOT_READY = "SCHEDULER_NOT_READY"
EVENT_BUS_NOT_READY = "EVENT_BUS_NOT_READY"
AGENT_RUNTIME_NOT_READY = "AGENT_RUNTIME_NOT_READY"
MISSING_GOVERNANCE_METADATA = "MISSING_GOVERNANCE_METADATA"


@dataclass(frozen=True)
class RuntimeHealthRequest:
    tenant_id: str
    policy_hash: str
    evidence_hash: str
    policy_available: bool
    audit_ready: bool
    tmux_available: bool | None
    scheduler_ready: bool
    event_bus_ready: bool
    agent_runtime_ready: bool


@dataclass(frozen=True)
class RuntimeHealthDecision:
    health_hash: str
    health_state: str
    check_hashes: Mapping[str, str]
    denial_reasons: tuple[str, ...]
    hash_only: bool = True
    redacted: bool = True
    execution_allowed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "health_hash": self.health_hash,
            "health_state": self.health_state,
            "check_hashes": dict(self.check_hashes),
            "denial_reasons": self.denial_reasons,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
            "execution_allowed": self.execution_allowed,
        }


def evaluate_runtime_health(request: RuntimeHealthRequest) -> RuntimeHealthDecision:
    """Evaluate deterministic runtime health from supplied metadata."""

    reasons = tuple(sorted(set(_denial_reasons(request))))
    health_state = _health_state(request, reasons)
    check_hashes = {
        "policy_availability": _hash_text(str(request.policy_available).lower()),
        "audit_readiness": _hash_text(str(request.audit_ready).lower()),
        "tmux_availability": _hash_text("unknown" if request.tmux_available is None else str(request.tmux_available).lower()),
        "scheduler_readiness": _hash_text(str(request.scheduler_ready).lower()),
        "event_bus_readiness": _hash_text(str(request.event_bus_ready).lower()),
        "agent_runtime_readiness": _hash_text(str(request.agent_runtime_ready).lower()),
    }
    payload = {
        "tenant_hash": _hash_text(request.tenant_id),
        "policy_hash": request.policy_hash,
        "evidence_hash": request.evidence_hash,
        "health_state": health_state,
        "check_hashes": check_hashes,
        "denial_reasons": reasons,
        "execution_allowed": False,
        "hash_only": True,
        "redacted": True,
    }
    return RuntimeHealthDecision(
        health_hash=_canonical_hash(payload),
        health_state=health_state,
        check_hashes=check_hashes,
        denial_reasons=reasons,
    )


def _denial_reasons(request: RuntimeHealthRequest) -> tuple[str, ...]:
    reasons: list[str] = []
    if not all((request.tenant_id, request.policy_hash, request.evidence_hash)):
        reasons.append(MISSING_GOVERNANCE_METADATA)
    if not request.policy_available:
        reasons.append(POLICY_UNAVAILABLE)
    if not request.audit_ready:
        reasons.append(AUDIT_NOT_READY)
    if request.tmux_available is None:
        reasons.append(TMUX_UNKNOWN)
    if not request.scheduler_ready:
        reasons.append(SCHEDULER_NOT_READY)
    if not request.event_bus_ready:
        reasons.append(EVENT_BUS_NOT_READY)
    if not request.agent_runtime_ready:
        reasons.append(AGENT_RUNTIME_NOT_READY)
    return tuple(reasons)


def _health_state(request: RuntimeHealthRequest, reasons: tuple[str, ...]) -> str:
    if MISSING_GOVERNANCE_METADATA in reasons or POLICY_UNAVAILABLE in reasons or AUDIT_NOT_READY in reasons:
        return BLOCKED
    if request.tmux_available is None:
        return UNKNOWN
    if reasons:
        return DEGRADED
    return HEALTHY


def _hash_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()
