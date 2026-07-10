"""Hash-only governance event bus metadata.

Events are immutable dataclass objects and are appended by returning a new tuple.
This module does not use sockets, brokers, Redis, Kafka, networking, or runtime
execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any, Mapping, Sequence


EVENT_READY = "EVENT_READY"
EVENT_BLOCKED = "EVENT_BLOCKED"

MISSING_EVENT_FIELD = "MISSING_EVENT_FIELD"
RAW_PAYLOAD_FORBIDDEN = "RAW_PAYLOAD_FORBIDDEN"
MUTATION_FORBIDDEN = "MUTATION_FORBIDDEN"
EXECUTION_REQUESTED = "EXECUTION_REQUESTED"

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
class GovernanceEvent:
    policy_hash: str
    tenant_hash: str
    evidence_hash: str
    correlation_id: str
    timestamp: str
    actor: str
    route: str
    decision_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    requested_execution: bool = False


@dataclass(frozen=True)
class EventAppendDecision:
    event_hash: str
    event_state: str
    events: tuple[GovernanceEvent, ...]
    event_count: int
    denial_reasons: tuple[str, ...]
    hash_only: bool = True
    redacted: bool = True
    execution_allowed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_hash": self.event_hash,
            "event_state": self.event_state,
            "event_count": self.event_count,
            "denial_reasons": self.denial_reasons,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
            "execution_allowed": self.execution_allowed,
        }


def append_governance_event(
    existing_events: Sequence[GovernanceEvent],
    event: GovernanceEvent,
) -> EventAppendDecision:
    """Append an immutable governance event by returning new event metadata."""

    reasons = tuple(sorted(set(_event_denials(event))))
    event_state = EVENT_BLOCKED if reasons else EVENT_READY
    events = tuple(existing_events) if reasons else tuple(existing_events) + (event,)
    payload = {
        "event": _event_payload(event),
        "event_count": len(events),
        "denial_reasons": reasons,
        "hash_only": True,
        "redacted": True,
        "execution_allowed": False,
    }
    return EventAppendDecision(
        event_hash=_canonical_hash(payload),
        event_state=event_state,
        events=events,
        event_count=len(events),
        denial_reasons=reasons,
    )


def _event_denials(event: GovernanceEvent) -> tuple[str, ...]:
    reasons: list[str] = []
    required = (
        event.policy_hash,
        event.tenant_hash,
        event.evidence_hash,
        event.correlation_id,
        event.timestamp,
        event.actor,
        event.route,
        event.decision_id,
    )
    if not all(required):
        reasons.append(MISSING_EVENT_FIELD)
    if event.requested_execution:
        reasons.append(EXECUTION_REQUESTED)
    if _contains_raw_payload(event.metadata):
        reasons.append(RAW_PAYLOAD_FORBIDDEN)
    return tuple(reasons)


def _event_payload(event: GovernanceEvent) -> Mapping[str, Any]:
    return {
        "policy_hash": event.policy_hash,
        "tenant_hash": event.tenant_hash,
        "evidence_hash": event.evidence_hash,
        "correlation_hash": _hash_text(event.correlation_id),
        "timestamp_hash": _hash_text(event.timestamp),
        "actor_hash": _hash_text(event.actor),
        "route_hash": _hash_text(event.route),
        "decision_hash": _hash_text(event.decision_id),
    }


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
