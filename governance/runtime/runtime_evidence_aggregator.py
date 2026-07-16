"""Deterministic Runtime Evidence Aggregator metadata.

The aggregator combines approved Phase B component evidence references into one
hash-only runtime evidence decision. It never executes work, opens sockets,
spawns processes, starts threads, calls providers, or activates production.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Mapping, Sequence


AGGREGATOR_NAME = "runtime_evidence_aggregator"
EVIDENCE_AGGREGATED = "EVIDENCE_AGGREGATED"
EVIDENCE_BLOCKED = "EVIDENCE_BLOCKED"
SUPPORTED_HASH_ALGORITHM = "sha256"
SUPPORTED_SCHEMA_VERSION = "phase-b.runtime-evidence-aggregator.v1"
SUPPORTED_EVIDENCE_VERSION = "phase-b.runtime-evidence.v1"

COMPONENT_ORDER = (
    "agent_runtime",
    "runtime_coordinator",
    "event_bus",
    "runtime_health",
    "execution_scheduler",
)
COMPONENT_ALLOW_LIST = frozenset(COMPONENT_ORDER)

MISSING_COMPONENT_EVIDENCE = "MISSING_COMPONENT_EVIDENCE"
UNKNOWN_COMPONENT = "UNKNOWN_COMPONENT"
DUPLICATE_COMPONENT = "DUPLICATE_COMPONENT"
MALFORMED_EVIDENCE = "MALFORMED_EVIDENCE"
MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
INVALID_HASH = "INVALID_HASH"
UNSUPPORTED_HASH_ALGORITHM = "UNSUPPORTED_HASH_ALGORITHM"
UNSUPPORTED_SCHEMA_VERSION = "UNSUPPORTED_SCHEMA_VERSION"
UNSUPPORTED_EVIDENCE_VERSION = "UNSUPPORTED_EVIDENCE_VERSION"
POLICY_HASH_MISMATCH = "POLICY_HASH_MISMATCH"
TENANT_HASH_MISMATCH = "TENANT_HASH_MISMATCH"
RUNTIME_METADATA_MISMATCH = "RUNTIME_METADATA_MISMATCH"
TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
TIMESTAMP_ORDER_INVALID = "TIMESTAMP_ORDER_INVALID"
NON_HASH_ONLY_EVIDENCE = "NON_HASH_ONLY_EVIDENCE"
UNREDACTED_EVIDENCE = "UNREDACTED_EVIDENCE"
EXECUTION_FLAG_ENABLED = "EXECUTION_FLAG_ENABLED"
PROVIDER_EXECUTION_ENABLED = "PROVIDER_EXECUTION_ENABLED"
PRODUCTION_ACTIVATION_ENABLED = "PRODUCTION_ACTIVATION_ENABLED"
RAW_PAYLOAD_PRESENT = "RAW_PAYLOAD_PRESENT"
SENSITIVE_DATA_PRESENT = "SENSITIVE_DATA_PRESENT"
AGGREGATION_FAILED_CLOSED = "AGGREGATION_FAILED_CLOSED"

DENIAL_CODES = (
    MISSING_COMPONENT_EVIDENCE,
    UNKNOWN_COMPONENT,
    DUPLICATE_COMPONENT,
    MALFORMED_EVIDENCE,
    MISSING_REQUIRED_FIELD,
    INVALID_FIELD_TYPE,
    INVALID_HASH,
    UNSUPPORTED_HASH_ALGORITHM,
    UNSUPPORTED_SCHEMA_VERSION,
    UNSUPPORTED_EVIDENCE_VERSION,
    POLICY_HASH_MISMATCH,
    TENANT_HASH_MISMATCH,
    RUNTIME_METADATA_MISMATCH,
    TIMESTAMP_INVALID,
    TIMESTAMP_ORDER_INVALID,
    NON_HASH_ONLY_EVIDENCE,
    UNREDACTED_EVIDENCE,
    EXECUTION_FLAG_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    PRODUCTION_ACTIVATION_ENABLED,
    RAW_PAYLOAD_PRESENT,
    SENSITIVE_DATA_PRESENT,
    AGGREGATION_FAILED_CLOSED,
)

REQUIRED_FIELDS = frozenset({
    "component",
    "evidence_hash",
    "policy_hash",
    "tenant_hash",
    "decision_hash",
    "timestamp",
    "schema_version",
    "evidence_version",
    "hash_algorithm",
    "redacted",
    "hash_only",
    "execution_allowed",
    "provider_execution",
    "production_activation",
})

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SENSITIVE_KEYS = frozenset({
    "api_key",
    "body",
    "content",
    "credential",
    "credentials",
    "customer_data",
    "email",
    "password",
    "payload",
    "personal_data",
    "private_key",
    "prompt",
    "prompts",
    "provider_data",
    "raw",
    "raw_payload",
    "secret",
    "sensitive",
    "sensitive_data",
    "token",
})


@dataclass(frozen=True)
class RuntimeEvidenceReference:
    component: str
    evidence_hash: str
    policy_hash: str
    tenant_hash: str
    decision_hash: str
    timestamp: str
    schema_version: str = SUPPORTED_SCHEMA_VERSION
    evidence_version: str = SUPPORTED_EVIDENCE_VERSION
    hash_algorithm: str = SUPPORTED_HASH_ALGORITHM
    redacted: bool = True
    hash_only: bool = True
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "evidence_hash": self.evidence_hash,
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "decision_hash": self.decision_hash,
            "timestamp": self.timestamp,
            "schema_version": self.schema_version,
            "evidence_version": self.evidence_version,
            "hash_algorithm": self.hash_algorithm,
            "redacted": self.redacted,
            "hash_only": self.hash_only,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
        }


@dataclass(frozen=True)
class RuntimeEvidenceAggregationDecision:
    aggregator: str
    component_order: tuple[str, ...]
    component_count: int
    component_evidence_hashes: Mapping[str, str]
    policy_hash: str | None
    tenant_hash: str | None
    aggregate_decision_hash: str
    aggregate_evidence_hash: str
    earliest_timestamp: str | None
    latest_timestamp: str | None
    schema_version: str
    evidence_version: str
    hash_algorithm: str
    hash_only: bool
    redacted: bool
    execution_allowed: bool
    provider_execution: bool
    production_activation: bool
    status: str
    denial_code: str | None
    denial_reasons: tuple[str, ...]
    remaining_gaps: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "aggregator": self.aggregator,
            "component_order": self.component_order,
            "component_count": self.component_count,
            "component_evidence_hashes": dict(self.component_evidence_hashes),
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "aggregate_decision_hash": self.aggregate_decision_hash,
            "aggregate_evidence_hash": self.aggregate_evidence_hash,
            "earliest_timestamp": self.earliest_timestamp,
            "latest_timestamp": self.latest_timestamp,
            "schema_version": self.schema_version,
            "evidence_version": self.evidence_version,
            "hash_algorithm": self.hash_algorithm,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "status": self.status,
            "denial_code": self.denial_code,
            "denial_reasons": self.denial_reasons,
            "remaining_gaps": self.remaining_gaps,
        }


def aggregate_runtime_evidence(
    references: Sequence[RuntimeEvidenceReference | Mapping[str, Any]],
) -> RuntimeEvidenceAggregationDecision:
    """Return deterministic aggregate evidence metadata for Phase B references."""

    normalized, reasons = _normalize_references(references)
    reasons.extend(_collection_denials(normalized))
    if not reasons:
        reasons.extend(_chronology_denials(normalized))
    denial_reasons = tuple(sorted(set(reasons)))
    if denial_reasons:
        return _blocked_decision(normalized, denial_reasons)
    return _aggregated_decision(normalized)


def _normalize_references(
    references: Sequence[RuntimeEvidenceReference | Mapping[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    normalized: dict[str, dict[str, Any]] = {}
    reasons: list[str] = []
    seen: set[str] = set()
    if not isinstance(references, Sequence) or isinstance(references, (str, bytes)):
        return {}, [MALFORMED_EVIDENCE]
    for reference in references:
        if isinstance(reference, RuntimeEvidenceReference):
            payload = reference.as_dict()
        elif isinstance(reference, Mapping):
            payload = dict(reference)
        else:
            reasons.append(MALFORMED_EVIDENCE)
            continue
        if _contains_sensitive_data(payload):
            reasons.append(SENSITIVE_DATA_PRESENT)
        if _contains_raw_payload(payload):
            reasons.append(RAW_PAYLOAD_PRESENT)
        missing_fields = REQUIRED_FIELDS.difference(payload)
        if missing_fields:
            reasons.append(MISSING_REQUIRED_FIELD)
        component = payload.get("component")
        if not isinstance(component, str):
            reasons.append(INVALID_FIELD_TYPE)
            continue
        if component in seen:
            reasons.append(DUPLICATE_COMPONENT)
        seen.add(component)
        if component not in COMPONENT_ALLOW_LIST:
            reasons.append(UNKNOWN_COMPONENT)
        field_reasons = _field_denials(payload)
        reasons.extend(field_reasons)
        if component in COMPONENT_ALLOW_LIST and component not in normalized:
            normalized[component] = payload
    return normalized, reasons


def _field_denials(payload: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in payload:
            continue
        value = payload[field]
        if field in {"component", "evidence_hash", "policy_hash", "tenant_hash", "decision_hash", "timestamp", "schema_version", "evidence_version", "hash_algorithm"} and not isinstance(value, str):
            reasons.append(INVALID_FIELD_TYPE)
        if field in {"redacted", "hash_only", "execution_allowed", "provider_execution", "production_activation"} and not isinstance(value, bool):
            reasons.append(INVALID_FIELD_TYPE)
    for field in ("evidence_hash", "policy_hash", "tenant_hash", "decision_hash"):
        value = payload.get(field)
        if isinstance(value, str) and not _HASH_RE.match(value):
            reasons.append(INVALID_HASH)
    timestamp = payload.get("timestamp")
    if isinstance(timestamp, str) and not _TIMESTAMP_RE.match(timestamp):
        reasons.append(TIMESTAMP_INVALID)
    if payload.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(UNSUPPORTED_HASH_ALGORITHM)
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        reasons.append(UNSUPPORTED_SCHEMA_VERSION)
    if payload.get("evidence_version") != SUPPORTED_EVIDENCE_VERSION:
        reasons.append(UNSUPPORTED_EVIDENCE_VERSION)
    if payload.get("hash_only") is not True:
        reasons.append(NON_HASH_ONLY_EVIDENCE)
    if payload.get("redacted") is not True:
        reasons.append(UNREDACTED_EVIDENCE)
    if payload.get("execution_allowed") is not False:
        reasons.append(EXECUTION_FLAG_ENABLED)
    if payload.get("provider_execution") is not False:
        reasons.append(PROVIDER_EXECUTION_ENABLED)
    if payload.get("production_activation") is not False:
        reasons.append(PRODUCTION_ACTIVATION_ENABLED)
    return tuple(reasons)


def _collection_denials(normalized: Mapping[str, Mapping[str, Any]]) -> tuple[str, ...]:
    reasons: list[str] = []
    if set(normalized) != COMPONENT_ALLOW_LIST:
        reasons.append(MISSING_COMPONENT_EVIDENCE)
    policy_hashes = {payload.get("policy_hash") for payload in normalized.values()}
    tenant_hashes = {payload.get("tenant_hash") for payload in normalized.values()}
    context_hashes = {(payload.get("policy_hash"), payload.get("tenant_hash")) for payload in normalized.values()}
    if len(policy_hashes) > 1:
        reasons.append(POLICY_HASH_MISMATCH)
    if len(tenant_hashes) > 1:
        reasons.append(TENANT_HASH_MISMATCH)
    if len(context_hashes) > 1:
        reasons.append(RUNTIME_METADATA_MISMATCH)
    return tuple(reasons)


def _chronology_denials(normalized: Mapping[str, Mapping[str, Any]]) -> tuple[str, ...]:
    timestamps = [normalized[component]["timestamp"] for component in COMPONENT_ORDER]
    if timestamps != sorted(timestamps):
        return (TIMESTAMP_ORDER_INVALID,)
    return ()


def _aggregated_decision(normalized: Mapping[str, Mapping[str, Any]]) -> RuntimeEvidenceAggregationDecision:
    ordered = tuple(normalized[component] for component in COMPONENT_ORDER)
    component_evidence_hashes = {
        component: normalized[component]["evidence_hash"] for component in COMPONENT_ORDER
    }
    timestamps = tuple(payload["timestamp"] for payload in ordered)
    payload = {
        "aggregator": AGGREGATOR_NAME,
        "component_order": COMPONENT_ORDER,
        "component_evidence_hashes": component_evidence_hashes,
        "component_decision_hashes": {
            component: normalized[component]["decision_hash"] for component in COMPONENT_ORDER
        },
        "policy_hash": ordered[0]["policy_hash"],
        "tenant_hash": ordered[0]["tenant_hash"],
        "earliest_timestamp": timestamps[0],
        "latest_timestamp": timestamps[-1],
        "schema_version": SUPPORTED_SCHEMA_VERSION,
        "evidence_version": SUPPORTED_EVIDENCE_VERSION,
        "hash_algorithm": SUPPORTED_HASH_ALGORITHM,
        "hash_only": True,
        "redacted": True,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "status": EVIDENCE_AGGREGATED,
    }
    aggregate_decision_hash = _canonical_hash(payload)
    aggregate_evidence_hash = _canonical_hash({
        "aggregate_decision_hash": aggregate_decision_hash,
        "component_evidence_hashes": component_evidence_hashes,
        "status": EVIDENCE_AGGREGATED,
    })
    return RuntimeEvidenceAggregationDecision(
        aggregator=AGGREGATOR_NAME,
        component_order=COMPONENT_ORDER,
        component_count=len(COMPONENT_ORDER),
        component_evidence_hashes=component_evidence_hashes,
        policy_hash=ordered[0]["policy_hash"],
        tenant_hash=ordered[0]["tenant_hash"],
        aggregate_decision_hash=aggregate_decision_hash,
        aggregate_evidence_hash=aggregate_evidence_hash,
        earliest_timestamp=timestamps[0],
        latest_timestamp=timestamps[-1],
        schema_version=SUPPORTED_SCHEMA_VERSION,
        evidence_version=SUPPORTED_EVIDENCE_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        hash_only=True,
        redacted=True,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        status=EVIDENCE_AGGREGATED,
        denial_code=None,
        denial_reasons=(),
        remaining_gaps=("human_approval_remains_external", "no_runtime_authorization"),
    )


def _blocked_decision(
    normalized: Mapping[str, Mapping[str, Any]],
    denial_reasons: tuple[str, ...],
) -> RuntimeEvidenceAggregationDecision:
    component_evidence_hashes = {
        component: normalized[component].get("evidence_hash", _hash_text(f"missing:{component}"))
        for component in COMPONENT_ORDER
        if component in normalized
    }
    denial_code = denial_reasons[0] if denial_reasons else AGGREGATION_FAILED_CLOSED
    payload = {
        "aggregator": AGGREGATOR_NAME,
        "component_order": COMPONENT_ORDER,
        "component_evidence_hashes": component_evidence_hashes,
        "denial_code": denial_code,
        "denial_reasons": denial_reasons,
        "status": EVIDENCE_BLOCKED,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "hash_only": True,
        "redacted": True,
    }
    aggregate_decision_hash = _canonical_hash(payload)
    return RuntimeEvidenceAggregationDecision(
        aggregator=AGGREGATOR_NAME,
        component_order=COMPONENT_ORDER,
        component_count=len(component_evidence_hashes),
        component_evidence_hashes=component_evidence_hashes,
        policy_hash=_single_value(normalized, "policy_hash"),
        tenant_hash=_single_value(normalized, "tenant_hash"),
        aggregate_decision_hash=aggregate_decision_hash,
        aggregate_evidence_hash=_canonical_hash({"blocked_aggregate_decision_hash": aggregate_decision_hash}),
        earliest_timestamp=_timestamp_boundary(normalized, first=True),
        latest_timestamp=_timestamp_boundary(normalized, first=False),
        schema_version=SUPPORTED_SCHEMA_VERSION,
        evidence_version=SUPPORTED_EVIDENCE_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        hash_only=True,
        redacted=True,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        status=EVIDENCE_BLOCKED,
        denial_code=denial_code,
        denial_reasons=denial_reasons,
        remaining_gaps=("aggregation_blocked_until_metadata_is_valid",),
    )


def _single_value(normalized: Mapping[str, Mapping[str, Any]], field: str) -> str | None:
    values = {payload.get(field) for payload in normalized.values() if isinstance(payload.get(field), str)}
    return values.pop() if len(values) == 1 else None


def _timestamp_boundary(normalized: Mapping[str, Mapping[str, Any]], *, first: bool) -> str | None:
    timestamps = [
        payload["timestamp"] for payload in normalized.values()
        if isinstance(payload.get("timestamp"), str) and _TIMESTAMP_RE.match(payload["timestamp"])
    ]
    if not timestamps:
        return None
    return sorted(timestamps)[0 if first else -1]


def _contains_raw_payload(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).lower() in {"raw", "raw_payload", "payload", "body", "content"} or _contains_raw_payload(child) for key, child in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_raw_payload(item) for item in value)
    return False


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
