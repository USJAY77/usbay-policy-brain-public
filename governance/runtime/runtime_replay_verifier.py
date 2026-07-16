"""Deterministic Runtime Replay Verifier metadata.

The verifier reconstructs recorded runtime governance decisions from hash-only
metadata. It never executes, dispatches, approves, activates, retries,
schedules, calls providers, or communicates over a network.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Mapping, Sequence


VERIFIER_NAME = "runtime_replay_verifier"
SUPPORTED_SCHEMA_VERSION = "phase-b.runtime-replay-verifier.v1"
SUPPORTED_EVIDENCE_VERSION = "phase-b.runtime-replay.v1"
SUPPORTED_HASH_ALGORITHM = "sha256"

REPLAY_VERIFIED = "REPLAY_VERIFIED"
REPLAY_DENIED = "REPLAY_DENIED"
REPLAY_HASH_MISMATCH = "REPLAY_HASH_MISMATCH"
REPLAY_POLICY_MISMATCH = "REPLAY_POLICY_MISMATCH"
REPLAY_TENANT_MISMATCH = "REPLAY_TENANT_MISMATCH"
REPLAY_EVIDENCE_MISMATCH = "REPLAY_EVIDENCE_MISMATCH"
REPLAY_APPROVAL_MISMATCH = "REPLAY_APPROVAL_MISMATCH"
REPLAY_DECISION_MISMATCH = "REPLAY_DECISION_MISMATCH"
REPLAY_CHAIN_BROKEN = "REPLAY_CHAIN_BROKEN"
REPLAY_TIMESTAMP_INVALID = "REPLAY_TIMESTAMP_INVALID"
REPLAY_SCHEMA_INVALID = "REPLAY_SCHEMA_INVALID"
REPLAY_DUPLICATE = "REPLAY_DUPLICATE"
REPLAY_MALFORMED = "REPLAY_MALFORMED"
REPLAY_UNKNOWN_INPUT = "REPLAY_UNKNOWN_INPUT"

ALLOWED_OUTCOMES = frozenset({
    REPLAY_VERIFIED,
    REPLAY_DENIED,
    REPLAY_HASH_MISMATCH,
    REPLAY_POLICY_MISMATCH,
    REPLAY_TENANT_MISMATCH,
    REPLAY_EVIDENCE_MISMATCH,
    REPLAY_APPROVAL_MISMATCH,
    REPLAY_DECISION_MISMATCH,
    REPLAY_CHAIN_BROKEN,
    REPLAY_TIMESTAMP_INVALID,
    REPLAY_SCHEMA_INVALID,
    REPLAY_DUPLICATE,
    REPLAY_MALFORMED,
    REPLAY_UNKNOWN_INPUT,
})

COMPONENT_ORDER = (
    "agent_runtime",
    "runtime_coordinator",
    "event_bus",
    "runtime_health",
    "execution_scheduler",
    "runtime_evidence_aggregator",
    "runtime_policy_binding",
    "runtime_approval_gate",
)
COMPONENT_ALLOW_LIST = frozenset(COMPONENT_ORDER)

REQUIRED_REQUEST_FIELDS = frozenset({
    "replay_id",
    "original_decision_id",
    "actor",
    "action",
    "policy_hash",
    "tenant_hash",
    "evidence_hash",
    "approval_hash",
    "decision_hash",
    "previous_decision_hash",
    "timestamp",
    "original_timestamp",
    "schema_version",
    "evidence_version",
    "hash_algorithm",
    "expected_outcome",
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "redacted",
    "hash_only",
    "component_references",
    "recorded_replay_hash",
})

REQUIRED_COMPONENT_FIELDS = frozenset({
    "component",
    "policy_hash",
    "tenant_hash",
    "evidence_hash",
    "approval_hash",
    "decision_hash",
    "previous_decision_hash",
    "schema_version",
    "evidence_version",
    "hash_algorithm",
    "timestamp",
    "redacted",
    "hash_only",
    "execution_allowed",
    "provider_execution",
    "production_activation",
})

MISSING_METADATA = "MISSING_METADATA"
UNKNOWN_METADATA = "UNKNOWN_METADATA"
MALFORMED_METADATA = "MALFORMED_METADATA"
DUPLICATE_REPLAY_ID = "DUPLICATE_REPLAY_ID"
REPLAY_ID_REUSE_MISMATCH = "REPLAY_ID_REUSE_MISMATCH"
INVALID_HASH = "INVALID_HASH"
POLICY_MISMATCH = "POLICY_MISMATCH"
TENANT_MISMATCH = "TENANT_MISMATCH"
EVIDENCE_MISMATCH = "EVIDENCE_MISMATCH"
APPROVAL_MISMATCH = "APPROVAL_MISMATCH"
DECISION_MISMATCH = "DECISION_MISMATCH"
CHAIN_BROKEN = "CHAIN_BROKEN"
TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
CHRONOLOGY_INVALID = "CHRONOLOGY_INVALID"
SCHEMA_VERSION_UNSUPPORTED = "SCHEMA_VERSION_UNSUPPORTED"
EVIDENCE_VERSION_UNSUPPORTED = "EVIDENCE_VERSION_UNSUPPORTED"
HASH_ALGORITHM_UNSUPPORTED = "HASH_ALGORITHM_UNSUPPORTED"
NON_REDACTED_EVIDENCE = "NON_REDACTED_EVIDENCE"
NON_HASH_ONLY_EVIDENCE = "NON_HASH_ONLY_EVIDENCE"
EXECUTION_FLAG_ENABLED = "EXECUTION_FLAG_ENABLED"
PROVIDER_EXECUTION_ENABLED = "PROVIDER_EXECUTION_ENABLED"
PRODUCTION_ACTIVATION_ENABLED = "PRODUCTION_ACTIVATION_ENABLED"
UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"
REORDERED_EVIDENCE = "REORDERED_EVIDENCE"
OMITTED_EVIDENCE = "OMITTED_EVIDENCE"
DUPLICATE_EVIDENCE = "DUPLICATE_EVIDENCE"
STALE_APPROVAL = "STALE_APPROVAL"
RAW_OR_SENSITIVE_DATA_PRESENT = "RAW_OR_SENSITIVE_DATA_PRESENT"

DENIAL_CODES = (
    MISSING_METADATA,
    UNKNOWN_METADATA,
    MALFORMED_METADATA,
    DUPLICATE_REPLAY_ID,
    REPLAY_ID_REUSE_MISMATCH,
    INVALID_HASH,
    POLICY_MISMATCH,
    TENANT_MISMATCH,
    EVIDENCE_MISMATCH,
    APPROVAL_MISMATCH,
    DECISION_MISMATCH,
    CHAIN_BROKEN,
    TIMESTAMP_INVALID,
    CHRONOLOGY_INVALID,
    SCHEMA_VERSION_UNSUPPORTED,
    EVIDENCE_VERSION_UNSUPPORTED,
    HASH_ALGORITHM_UNSUPPORTED,
    NON_REDACTED_EVIDENCE,
    NON_HASH_ONLY_EVIDENCE,
    EXECUTION_FLAG_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    PRODUCTION_ACTIVATION_ENABLED,
    UNKNOWN_OUTCOME,
    REORDERED_EVIDENCE,
    OMITTED_EVIDENCE,
    DUPLICATE_EVIDENCE,
    STALE_APPROVAL,
    RAW_OR_SENSITIVE_DATA_PRESENT,
)

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,80}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SENSITIVE_KEYS = frozenset({
    "api_key",
    "approval_content",
    "body",
    "comment",
    "content",
    "credential",
    "credentials",
    "email",
    "name",
    "password",
    "payload",
    "prompt",
    "raw",
    "raw_payload",
    "secret",
    "sensitive",
    "token",
})


@dataclass(frozen=True)
class RuntimeReplayRequest:
    replay_id: str
    original_decision_id: str
    actor: str
    action: str
    policy_hash: str
    tenant_hash: str
    evidence_hash: str
    approval_hash: str
    decision_hash: str
    previous_decision_hash: str
    timestamp: str
    original_timestamp: str
    schema_version: str
    evidence_version: str
    hash_algorithm: str
    expected_outcome: str
    execution_allowed: bool
    provider_execution: bool
    production_activation: bool
    redacted: bool
    hash_only: bool
    component_references: Sequence[Mapping[str, Any]]
    recorded_replay_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "replay_id": self.replay_id,
            "original_decision_id": self.original_decision_id,
            "actor": self.actor,
            "action": self.action,
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "evidence_hash": self.evidence_hash,
            "approval_hash": self.approval_hash,
            "decision_hash": self.decision_hash,
            "previous_decision_hash": self.previous_decision_hash,
            "timestamp": self.timestamp,
            "original_timestamp": self.original_timestamp,
            "schema_version": self.schema_version,
            "evidence_version": self.evidence_version,
            "hash_algorithm": self.hash_algorithm,
            "expected_outcome": self.expected_outcome,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "redacted": self.redacted,
            "hash_only": self.hash_only,
            "component_references": tuple(dict(item) for item in self.component_references),
            "recorded_replay_hash": self.recorded_replay_hash,
        }


@dataclass(frozen=True)
class RuntimeReplayDecision:
    verifier: str
    replay_id_hash: str | None
    replay_hash: str
    reconstructed_decision_hash: str
    recorded_replay_hash: str | None
    policy_hash: str | None
    tenant_hash: str | None
    evidence_hash: str | None
    approval_hash: str | None
    component_order: tuple[str, ...]
    component_evidence_hashes: Mapping[str, str]
    status: str
    denial_code: str | None
    denial_reasons: tuple[str, ...]
    schema_version: str
    evidence_version: str
    hash_algorithm: str
    redacted: bool
    hash_only: bool
    execution_allowed: bool
    provider_execution: bool
    production_activation: bool
    remaining_gaps: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "verifier": self.verifier,
            "replay_id_hash": self.replay_id_hash,
            "replay_hash": self.replay_hash,
            "reconstructed_decision_hash": self.reconstructed_decision_hash,
            "recorded_replay_hash": self.recorded_replay_hash,
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "evidence_hash": self.evidence_hash,
            "approval_hash": self.approval_hash,
            "component_order": self.component_order,
            "component_evidence_hashes": dict(self.component_evidence_hashes),
            "status": self.status,
            "denial_code": self.denial_code,
            "denial_reasons": self.denial_reasons,
            "schema_version": self.schema_version,
            "evidence_version": self.evidence_version,
            "hash_algorithm": self.hash_algorithm,
            "redacted": self.redacted,
            "hash_only": self.hash_only,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "remaining_gaps": self.remaining_gaps,
        }


def verify_runtime_replay(
    request: RuntimeReplayRequest | Mapping[str, Any],
    prior_replays: Sequence[Mapping[str, Any]] = (),
) -> RuntimeReplayDecision:
    """Verify replay metadata deterministically without executing anything."""

    request_payload, request_reasons = _request_payload(request)
    components, component_reasons = _normalize_components(request_payload.get("component_references", ()))
    reasons = list(request_reasons)
    reasons.extend(component_reasons)
    reasons.extend(_supplied_order_denials(request_payload.get("component_references", ())))
    reasons.extend(_request_denials(request_payload))
    reasons.extend(_component_collection_denials(request_payload, components))
    reasons.extend(_prior_replay_denials(request_payload, prior_replays))
    if not reasons:
        reasons.extend(_chronology_denials(request_payload, components))
        reasons.extend(_chain_denials(request_payload, components))
    reconstructed_hash = reconstruct_replay_hash(request_payload, components)
    if not reasons and request_payload["recorded_replay_hash"] != reconstructed_hash:
        reasons.append(REPLAY_ID_REUSE_MISMATCH if _same_replay_id(prior_replays, request_payload) else REPLAY_HASH_MISMATCH)
    if not reasons and request_payload["decision_hash"] != _reconstructed_decision_hash(request_payload, components):
        reasons.append(DECISION_MISMATCH)
    denial_reasons = tuple(sorted(set(reasons)))
    if denial_reasons:
        return _blocked_decision(request_payload, components, reconstructed_hash, denial_reasons)
    return _verified_decision(request_payload, components, reconstructed_hash)


def reconstruct_replay_hash(
    request_payload: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
) -> str:
    """Build the canonical replay hash from request metadata."""

    payload = {
        "replay_id_hash": _hash_text(str(request_payload.get("replay_id", ""))),
        "original_decision_id_hash": _hash_text(str(request_payload.get("original_decision_id", ""))),
        "actor_hash": _hash_text(str(request_payload.get("actor", ""))),
        "action_hash": _hash_text(str(request_payload.get("action", ""))),
        "policy_hash": request_payload.get("policy_hash"),
        "tenant_hash": request_payload.get("tenant_hash"),
        "evidence_hash": request_payload.get("evidence_hash"),
        "approval_hash": request_payload.get("approval_hash"),
        "decision_hash": request_payload.get("decision_hash"),
        "previous_decision_hash": request_payload.get("previous_decision_hash"),
        "timestamp": request_payload.get("timestamp"),
        "original_timestamp": request_payload.get("original_timestamp"),
        "schema_version": request_payload.get("schema_version"),
        "evidence_version": request_payload.get("evidence_version"),
        "hash_algorithm": request_payload.get("hash_algorithm"),
        "expected_outcome": request_payload.get("expected_outcome"),
        "component_order": COMPONENT_ORDER,
        "component_hashes": {
            component: components[component]["evidence_hash"]
            for component in COMPONENT_ORDER
            if component in components
        },
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "redacted": True,
        "hash_only": True,
    }
    return _canonical_hash(payload)


def _request_payload(request: RuntimeReplayRequest | Mapping[str, Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
    if isinstance(request, RuntimeReplayRequest):
        payload = request.as_dict()
    elif isinstance(request, Mapping):
        payload = dict(request)
    else:
        return {}, (REPLAY_MALFORMED,)
    reasons: list[str] = []
    if REQUIRED_REQUEST_FIELDS.difference(payload):
        reasons.append(MISSING_METADATA)
    if set(payload).difference(REQUIRED_REQUEST_FIELDS):
        reasons.append(UNKNOWN_METADATA)
    if _contains_sensitive_data(payload):
        reasons.append(RAW_OR_SENSITIVE_DATA_PRESENT)
    return payload, tuple(reasons)


def _normalize_components(component_references: Any) -> tuple[dict[str, dict[str, Any]], list[str]]:
    components: dict[str, dict[str, Any]] = {}
    reasons: list[str] = []
    seen: set[str] = set()
    if not isinstance(component_references, Sequence) or isinstance(component_references, (str, bytes)):
        return {}, [REPLAY_MALFORMED]
    for reference in component_references:
        if not isinstance(reference, Mapping):
            reasons.append(REPLAY_MALFORMED)
            continue
        payload = dict(reference)
        if REQUIRED_COMPONENT_FIELDS.difference(payload):
            reasons.append(OMITTED_EVIDENCE)
        if set(payload).difference(REQUIRED_COMPONENT_FIELDS):
            reasons.append(UNKNOWN_METADATA)
        if _contains_sensitive_data(payload):
            reasons.append(RAW_OR_SENSITIVE_DATA_PRESENT)
        component = payload.get("component")
        if not isinstance(component, str):
            reasons.append(REPLAY_MALFORMED)
            continue
        if component in seen:
            reasons.append(DUPLICATE_EVIDENCE)
        seen.add(component)
        if component not in COMPONENT_ALLOW_LIST:
            reasons.append(REPLAY_UNKNOWN_INPUT)
        reasons.extend(_component_field_denials(payload))
        if component in COMPONENT_ALLOW_LIST and component not in components:
            components[component] = payload
    return components, reasons


def _request_denials(payload: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    for field in ("replay_id", "original_decision_id", "actor", "action", "timestamp", "original_timestamp", "schema_version", "evidence_version", "hash_algorithm", "expected_outcome"):
        if field in payload and not isinstance(payload[field], str):
            reasons.append(REPLAY_MALFORMED)
    for field in ("policy_hash", "tenant_hash", "evidence_hash", "approval_hash", "decision_hash", "previous_decision_hash", "recorded_replay_hash"):
        if not payload.get(field):
            reasons.append(MISSING_METADATA)
        elif isinstance(payload.get(field), str) and not _HASH_RE.match(payload[field]):
            reasons.append(INVALID_HASH)
    if isinstance(payload.get("replay_id"), str) and not _ID_RE.match(payload["replay_id"]):
        reasons.append(REPLAY_MALFORMED)
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        reasons.append(SCHEMA_VERSION_UNSUPPORTED)
    if payload.get("evidence_version") != SUPPORTED_EVIDENCE_VERSION:
        reasons.append(EVIDENCE_VERSION_UNSUPPORTED)
    if payload.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(HASH_ALGORITHM_UNSUPPORTED)
    if payload.get("expected_outcome") not in ALLOWED_OUTCOMES:
        reasons.append(UNKNOWN_OUTCOME)
    if payload.get("redacted") is not True:
        reasons.append(NON_REDACTED_EVIDENCE)
    if payload.get("hash_only") is not True:
        reasons.append(NON_HASH_ONLY_EVIDENCE)
    if payload.get("execution_allowed") is not False:
        reasons.append(EXECUTION_FLAG_ENABLED)
    if payload.get("provider_execution") is not False:
        reasons.append(PROVIDER_EXECUTION_ENABLED)
    if payload.get("production_activation") is not False:
        reasons.append(PRODUCTION_ACTIVATION_ENABLED)
    for field in ("timestamp", "original_timestamp"):
        if isinstance(payload.get(field), str) and not _TIMESTAMP_RE.match(payload[field]):
            reasons.append(TIMESTAMP_INVALID)
    return tuple(reasons)


def _component_field_denials(payload: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    for field in REQUIRED_COMPONENT_FIELDS:
        if field not in payload:
            continue
        value = payload[field]
        if field in {"component", "policy_hash", "tenant_hash", "evidence_hash", "approval_hash", "decision_hash", "previous_decision_hash", "schema_version", "evidence_version", "hash_algorithm", "timestamp"} and not isinstance(value, str):
            reasons.append(REPLAY_MALFORMED)
        if field in {"redacted", "hash_only", "execution_allowed", "provider_execution", "production_activation"} and not isinstance(value, bool):
            reasons.append(REPLAY_MALFORMED)
    for field in ("policy_hash", "tenant_hash", "evidence_hash", "approval_hash", "decision_hash", "previous_decision_hash"):
        if not payload.get(field):
            reasons.append(MISSING_METADATA)
        elif isinstance(payload.get(field), str) and not _HASH_RE.match(payload[field]):
            reasons.append(INVALID_HASH)
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        reasons.append(SCHEMA_VERSION_UNSUPPORTED)
    if payload.get("evidence_version") != SUPPORTED_EVIDENCE_VERSION:
        reasons.append(EVIDENCE_VERSION_UNSUPPORTED)
    if payload.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(HASH_ALGORITHM_UNSUPPORTED)
    if isinstance(payload.get("timestamp"), str) and not _TIMESTAMP_RE.match(payload["timestamp"]):
        reasons.append(TIMESTAMP_INVALID)
    if payload.get("redacted") is not True:
        reasons.append(NON_REDACTED_EVIDENCE)
    if payload.get("hash_only") is not True:
        reasons.append(NON_HASH_ONLY_EVIDENCE)
    if payload.get("execution_allowed") is not False:
        reasons.append(EXECUTION_FLAG_ENABLED)
    if payload.get("provider_execution") is not False:
        reasons.append(PROVIDER_EXECUTION_ENABLED)
    if payload.get("production_activation") is not False:
        reasons.append(PRODUCTION_ACTIVATION_ENABLED)
    return tuple(reasons)


def _component_collection_denials(
    request: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
) -> tuple[str, ...]:
    reasons: list[str] = []
    if set(components) != COMPONENT_ALLOW_LIST:
        reasons.append(OMITTED_EVIDENCE)
    if tuple(component for component in COMPONENT_ORDER if component in components) != COMPONENT_ORDER:
        reasons.append(REORDERED_EVIDENCE)
    for component in components.values():
        if component.get("policy_hash") != request.get("policy_hash"):
            reasons.append(POLICY_MISMATCH)
        if component.get("tenant_hash") != request.get("tenant_hash"):
            reasons.append(TENANT_MISMATCH)
        if component.get("approval_hash") != request.get("approval_hash"):
            reasons.append(APPROVAL_MISMATCH)
    aggregator = components.get("runtime_evidence_aggregator")
    approval_gate = components.get("runtime_approval_gate")
    if aggregator and aggregator.get("evidence_hash") != request.get("evidence_hash"):
        reasons.append(EVIDENCE_MISMATCH)
    if approval_gate and approval_gate.get("approval_hash") != request.get("approval_hash"):
        reasons.append(APPROVAL_MISMATCH)
    return tuple(reasons)


def _supplied_order_denials(component_references: Any) -> tuple[str, ...]:
    if not isinstance(component_references, Sequence) or isinstance(component_references, (str, bytes)):
        return ()
    supplied = tuple(
        reference.get("component")
        for reference in component_references
        if isinstance(reference, Mapping)
    )
    return () if supplied == COMPONENT_ORDER else (REORDERED_EVIDENCE,)


def _chronology_denials(
    request: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
) -> tuple[str, ...]:
    reasons: list[str] = []
    timestamp = request.get("timestamp")
    original = request.get("original_timestamp")
    if isinstance(timestamp, str) and isinstance(original, str):
        if timestamp < original:
            reasons.append(CHRONOLOGY_INVALID)
    component_timestamps = [components[component]["timestamp"] for component in COMPONENT_ORDER if component in components]
    if component_timestamps != sorted(component_timestamps):
        reasons.append(CHRONOLOGY_INVALID)
    approval_gate = components.get("runtime_approval_gate")
    if approval_gate and isinstance(timestamp, str) and approval_gate.get("timestamp", timestamp) < original:
        reasons.append(STALE_APPROVAL)
    return tuple(reasons)


def _chain_denials(
    request: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
) -> tuple[str, ...]:
    previous = request.get("previous_decision_hash")
    for component in COMPONENT_ORDER:
        if component not in components:
            continue
        payload = components[component]
        if payload.get("previous_decision_hash") != previous:
            return (CHAIN_BROKEN,)
        previous = payload.get("decision_hash")
    return ()


def _prior_replay_denials(
    request: Mapping[str, Any],
    prior_replays: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    reasons: list[str] = []
    for prior in prior_replays:
        if prior.get("replay_id") == request.get("replay_id"):
            if prior == request:
                reasons.append(DUPLICATE_REPLAY_ID)
            else:
                reasons.append(REPLAY_ID_REUSE_MISMATCH)
    return tuple(reasons)


def _same_replay_id(prior_replays: Sequence[Mapping[str, Any]], request: Mapping[str, Any]) -> bool:
    return any(prior.get("replay_id") == request.get("replay_id") for prior in prior_replays)


def _reconstructed_decision_hash(
    request: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
) -> str:
    payload = {
        "policy_hash": request.get("policy_hash"),
        "tenant_hash": request.get("tenant_hash"),
        "evidence_hash": request.get("evidence_hash"),
        "approval_hash": request.get("approval_hash"),
        "previous_decision_hash": request.get("previous_decision_hash"),
        "component_decisions": tuple(
            components[component]["decision_hash"]
            for component in COMPONENT_ORDER
            if component in components
        ),
        "expected_outcome": request.get("expected_outcome"),
    }
    return _canonical_hash(payload)


def _verified_decision(
    request: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
    replay_hash: str,
) -> RuntimeReplayDecision:
    return RuntimeReplayDecision(
        verifier=VERIFIER_NAME,
        replay_id_hash=_hash_text(request["replay_id"]),
        replay_hash=replay_hash,
        reconstructed_decision_hash=request["decision_hash"],
        recorded_replay_hash=request["recorded_replay_hash"],
        policy_hash=request["policy_hash"],
        tenant_hash=request["tenant_hash"],
        evidence_hash=request["evidence_hash"],
        approval_hash=request["approval_hash"],
        component_order=COMPONENT_ORDER,
        component_evidence_hashes={component: components[component]["evidence_hash"] for component in COMPONENT_ORDER},
        status=request["expected_outcome"],
        denial_code=None,
        denial_reasons=(),
        schema_version=SUPPORTED_SCHEMA_VERSION,
        evidence_version=SUPPORTED_EVIDENCE_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        redacted=True,
        hash_only=True,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        remaining_gaps=("replay_verification_does_not_authorize_execution",),
    )


def _blocked_decision(
    request: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
    replay_hash: str,
    denial_reasons: tuple[str, ...],
) -> RuntimeReplayDecision:
    component_evidence_hashes = {
        component: components[component].get("evidence_hash", _hash_text(f"missing:{component}"))
        for component in COMPONENT_ORDER
        if component in components
    }
    return RuntimeReplayDecision(
        verifier=VERIFIER_NAME,
        replay_id_hash=_hash_text(str(request.get("replay_id"))) if isinstance(request.get("replay_id"), str) else None,
        replay_hash=replay_hash,
        reconstructed_decision_hash=_reconstructed_decision_hash(request, components),
        recorded_replay_hash=request.get("recorded_replay_hash") if isinstance(request.get("recorded_replay_hash"), str) and _HASH_RE.match(request["recorded_replay_hash"]) else None,
        policy_hash=request.get("policy_hash") if isinstance(request.get("policy_hash"), str) and _HASH_RE.match(request["policy_hash"]) else None,
        tenant_hash=request.get("tenant_hash") if isinstance(request.get("tenant_hash"), str) and _HASH_RE.match(request["tenant_hash"]) else None,
        evidence_hash=request.get("evidence_hash") if isinstance(request.get("evidence_hash"), str) and _HASH_RE.match(request["evidence_hash"]) else None,
        approval_hash=request.get("approval_hash") if isinstance(request.get("approval_hash"), str) and _HASH_RE.match(request["approval_hash"]) else None,
        component_order=COMPONENT_ORDER,
        component_evidence_hashes=component_evidence_hashes,
        status=request.get("expected_outcome") if request.get("expected_outcome") in ALLOWED_OUTCOMES else REPLAY_UNKNOWN_INPUT,
        denial_code=denial_reasons[0],
        denial_reasons=denial_reasons,
        schema_version=SUPPORTED_SCHEMA_VERSION,
        evidence_version=SUPPORTED_EVIDENCE_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        redacted=True,
        hash_only=True,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        remaining_gaps=("replay_blocked_until_metadata_is_valid",),
    )


def _contains_sensitive_data(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).lower() in _SENSITIVE_KEYS or _contains_sensitive_data(child) for key, child in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive_data(item) for item in value)
    return False


def _hash_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()
