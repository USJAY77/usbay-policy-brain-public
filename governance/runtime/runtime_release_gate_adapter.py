"""Deterministic Runtime Release Gate Adapter metadata.

The adapter translates approved Phase B governance outputs into release
readiness metadata. It never authorizes execution, deploys, changes policy,
calls providers, or activates production.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Mapping, Sequence


ADAPTER_NAME = "runtime_release_gate_adapter"
RELEASE_READY_METADATA = "RELEASE_READY_METADATA"
RELEASE_BLOCKED = "RELEASE_BLOCKED"
SUPPORTED_SCHEMA_VERSION = "phase-b.runtime-release-gate-adapter.v1"
SUPPORTED_OUTPUT_VERSION = "phase-b.release-readiness.v1"
SUPPORTED_HASH_ALGORITHM = "sha256"
SUPPORTED_RELEASE_STAGES = frozenset({"LOCAL_REVIEW", "PR_REVIEW", "MERGE_REVIEW"})

COMPONENT_ORDER = (
    "agent_runtime",
    "runtime_coordinator",
    "event_bus",
    "runtime_health",
    "execution_scheduler",
    "runtime_evidence_aggregator",
    "runtime_policy_binding",
    "runtime_approval_gate",
    "runtime_replay_verifier",
)
COMPONENT_ALLOW_LIST = frozenset(COMPONENT_ORDER)

MISSING_EVIDENCE = "MISSING_EVIDENCE"
MISSING_APPROVAL = "MISSING_APPROVAL"
REPLAY_MISMATCH = "REPLAY_MISMATCH"
POLICY_MISMATCH = "POLICY_MISMATCH"
TENANT_MISMATCH = "TENANT_MISMATCH"
EVIDENCE_MISMATCH = "EVIDENCE_MISMATCH"
MALFORMED_METADATA = "MALFORMED_METADATA"
DUPLICATE_METADATA = "DUPLICATE_METADATA"
INVALID_CHRONOLOGY = "INVALID_CHRONOLOGY"
UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
UNSUPPORTED_HASH_ALGORITHM = "UNSUPPORTED_HASH_ALGORITHM"
UNKNOWN_COMPONENT = "UNKNOWN_COMPONENT"
UNKNOWN_STAGE = "UNKNOWN_STAGE"
UNKNOWN_METADATA = "UNKNOWN_METADATA"
INVALID_HASH = "INVALID_HASH"
NON_HASH_ONLY_EVIDENCE = "NON_HASH_ONLY_EVIDENCE"
UNREDACTED_EVIDENCE = "UNREDACTED_EVIDENCE"
EXECUTION_FLAG_ENABLED = "EXECUTION_FLAG_ENABLED"
PROVIDER_EXECUTION_ENABLED = "PROVIDER_EXECUTION_ENABLED"
PRODUCTION_ACTIVATION_ENABLED = "PRODUCTION_ACTIVATION_ENABLED"
SENSITIVE_DATA_PRESENT = "SENSITIVE_DATA_PRESENT"

DENIAL_CODES = (
    MISSING_EVIDENCE,
    MISSING_APPROVAL,
    REPLAY_MISMATCH,
    POLICY_MISMATCH,
    TENANT_MISMATCH,
    EVIDENCE_MISMATCH,
    MALFORMED_METADATA,
    DUPLICATE_METADATA,
    INVALID_CHRONOLOGY,
    UNSUPPORTED_SCHEMA,
    UNSUPPORTED_VERSION,
    UNSUPPORTED_HASH_ALGORITHM,
    UNKNOWN_COMPONENT,
    UNKNOWN_STAGE,
    UNKNOWN_METADATA,
    INVALID_HASH,
    NON_HASH_ONLY_EVIDENCE,
    UNREDACTED_EVIDENCE,
    EXECUTION_FLAG_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    PRODUCTION_ACTIVATION_ENABLED,
    SENSITIVE_DATA_PRESENT,
)

REQUIRED_REFERENCE_FIELDS = frozenset({
    "component",
    "policy_hash",
    "tenant_hash",
    "evidence_hash",
    "decision_hash",
    "timestamp",
    "schema_version",
    "output_version",
    "hash_algorithm",
    "hash_only",
    "redacted",
    "execution_allowed",
    "provider_execution",
    "production_activation",
})

REQUIRED_REQUEST_FIELDS = frozenset({
    "release_id",
    "policy_hash",
    "tenant_hash",
    "evidence_hash",
    "approval_hash",
    "replay_hash",
    "release_stage",
    "schema_version",
    "output_version",
    "hash_algorithm",
    "component_references",
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "hash_only",
    "redacted",
})

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^release-[a-z0-9][a-z0-9-]{2,80}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SENSITIVE_KEYS = frozenset({
    "api_key",
    "body",
    "content",
    "credential",
    "credentials",
    "password",
    "payload",
    "private_key",
    "raw",
    "raw_payload",
    "secret",
    "sensitive",
    "token",
})


@dataclass(frozen=True)
class RuntimeReleaseGateRequest:
    release_id: str
    policy_hash: str
    tenant_hash: str
    evidence_hash: str
    approval_hash: str
    replay_hash: str
    release_stage: str
    schema_version: str
    output_version: str
    hash_algorithm: str
    component_references: Sequence[Mapping[str, Any]]
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    hash_only: bool = True
    redacted: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "release_id": self.release_id,
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "evidence_hash": self.evidence_hash,
            "approval_hash": self.approval_hash,
            "replay_hash": self.replay_hash,
            "release_stage": self.release_stage,
            "schema_version": self.schema_version,
            "output_version": self.output_version,
            "hash_algorithm": self.hash_algorithm,
            "component_references": tuple(dict(item) for item in self.component_references),
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
        }


@dataclass(frozen=True)
class RuntimeReleaseGateDecision:
    adapter: str
    release_id_hash: str | None
    release_readiness_hash: str
    policy_hash: str | None
    tenant_hash: str | None
    evidence_hash: str | None
    approval_hash: str | None
    replay_hash: str | None
    release_stage: str
    component_order: tuple[str, ...]
    component_evidence_hashes: Mapping[str, str]
    readiness_state: str
    denial_code: str | None
    denial_reasons: tuple[str, ...]
    schema_version: str
    output_version: str
    hash_algorithm: str
    execution_allowed: bool
    provider_execution: bool
    production_activation: bool
    hash_only: bool
    redacted: bool
    remaining_gaps: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "release_id_hash": self.release_id_hash,
            "release_readiness_hash": self.release_readiness_hash,
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "evidence_hash": self.evidence_hash,
            "approval_hash": self.approval_hash,
            "replay_hash": self.replay_hash,
            "release_stage": self.release_stage,
            "component_order": self.component_order,
            "component_evidence_hashes": dict(self.component_evidence_hashes),
            "readiness_state": self.readiness_state,
            "denial_code": self.denial_code,
            "denial_reasons": self.denial_reasons,
            "schema_version": self.schema_version,
            "output_version": self.output_version,
            "hash_algorithm": self.hash_algorithm,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
            "remaining_gaps": self.remaining_gaps,
        }


def evaluate_runtime_release_gate(
    request: RuntimeReleaseGateRequest | Mapping[str, Any],
) -> RuntimeReleaseGateDecision:
    """Translate Phase B governance outputs into release readiness metadata."""

    payload, request_reasons = _request_payload(request)
    components, component_reasons = _normalize_components(payload.get("component_references", ()))
    reasons = list(request_reasons)
    reasons.extend(component_reasons)
    reasons.extend(_request_denials(payload))
    reasons.extend(_component_collection_denials(payload, components))
    if not reasons:
        reasons.extend(_chronology_denials(components))
    denial_reasons = tuple(sorted(set(reasons)))
    if denial_reasons:
        return _blocked_decision(payload, components, denial_reasons)
    return _ready_decision(payload, components)


def _request_payload(request: RuntimeReleaseGateRequest | Mapping[str, Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
    if isinstance(request, RuntimeReleaseGateRequest):
        payload = request.as_dict()
    elif isinstance(request, Mapping):
        payload = dict(request)
    else:
        return {}, (MALFORMED_METADATA,)
    reasons: list[str] = []
    if REQUIRED_REQUEST_FIELDS.difference(payload):
        reasons.append(MISSING_EVIDENCE)
    if set(payload).difference(REQUIRED_REQUEST_FIELDS):
        reasons.append(UNKNOWN_METADATA)
    if _contains_sensitive_data(payload):
        reasons.append(SENSITIVE_DATA_PRESENT)
    return payload, tuple(reasons)


def _normalize_components(component_references: Any) -> tuple[dict[str, dict[str, Any]], list[str]]:
    components: dict[str, dict[str, Any]] = {}
    reasons: list[str] = []
    seen: set[str] = set()
    if not isinstance(component_references, Sequence) or isinstance(component_references, (str, bytes)):
        return {}, [MALFORMED_METADATA]
    supplied_order: list[str] = []
    for reference in component_references:
        if not isinstance(reference, Mapping):
            reasons.append(MALFORMED_METADATA)
            continue
        payload = dict(reference)
        if REQUIRED_REFERENCE_FIELDS.difference(payload):
            reasons.append(MISSING_EVIDENCE)
        if set(payload).difference(REQUIRED_REFERENCE_FIELDS):
            reasons.append(UNKNOWN_METADATA)
        if _contains_sensitive_data(payload):
            reasons.append(SENSITIVE_DATA_PRESENT)
        component = payload.get("component")
        if not isinstance(component, str):
            reasons.append(MALFORMED_METADATA)
            continue
        supplied_order.append(component)
        if component in seen:
            reasons.append(DUPLICATE_METADATA)
        seen.add(component)
        if component not in COMPONENT_ALLOW_LIST:
            reasons.append(UNKNOWN_COMPONENT)
        reasons.extend(_reference_denials(payload))
        if component in COMPONENT_ALLOW_LIST and component not in components:
            components[component] = payload
    if tuple(supplied_order) != COMPONENT_ORDER:
        reasons.append(MALFORMED_METADATA)
    return components, reasons


def _request_denials(payload: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    release_id = payload.get("release_id")
    if not isinstance(release_id, str):
        reasons.append(MALFORMED_METADATA)
    elif not _ID_RE.match(release_id):
        reasons.append(MALFORMED_METADATA)
    if payload.get("release_stage") not in SUPPORTED_RELEASE_STAGES:
        reasons.append(UNKNOWN_STAGE)
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        reasons.append(UNSUPPORTED_SCHEMA)
    if payload.get("output_version") != SUPPORTED_OUTPUT_VERSION:
        reasons.append(UNSUPPORTED_VERSION)
    if payload.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(UNSUPPORTED_HASH_ALGORITHM)
    for field in ("policy_hash", "tenant_hash", "evidence_hash", "approval_hash", "replay_hash"):
        if not payload.get(field):
            reasons.append(MISSING_EVIDENCE if field != "approval_hash" else MISSING_APPROVAL)
        elif isinstance(payload.get(field), str) and not _HASH_RE.match(payload[field]):
            reasons.append(INVALID_HASH)
    reasons.extend(_flag_denials(payload))
    return tuple(reasons)


def _reference_denials(payload: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    for field in REQUIRED_REFERENCE_FIELDS:
        if field not in payload:
            continue
        value = payload[field]
        if field in {"component", "policy_hash", "tenant_hash", "evidence_hash", "decision_hash", "timestamp", "schema_version", "output_version", "hash_algorithm"} and not isinstance(value, str):
            reasons.append(MALFORMED_METADATA)
        if field in {"hash_only", "redacted", "execution_allowed", "provider_execution", "production_activation"} and not isinstance(value, bool):
            reasons.append(MALFORMED_METADATA)
    for field in ("policy_hash", "tenant_hash", "evidence_hash", "decision_hash"):
        if not payload.get(field):
            reasons.append(MISSING_EVIDENCE)
        elif isinstance(payload.get(field), str) and not _HASH_RE.match(payload[field]):
            reasons.append(INVALID_HASH)
    if isinstance(payload.get("timestamp"), str) and not _TIMESTAMP_RE.match(payload["timestamp"]):
        reasons.append(INVALID_CHRONOLOGY)
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        reasons.append(UNSUPPORTED_SCHEMA)
    if payload.get("output_version") != SUPPORTED_OUTPUT_VERSION:
        reasons.append(UNSUPPORTED_VERSION)
    if payload.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(UNSUPPORTED_HASH_ALGORITHM)
    reasons.extend(_flag_denials(payload))
    return tuple(reasons)


def _flag_denials(payload: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
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


def _component_collection_denials(
    request: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
) -> tuple[str, ...]:
    reasons: list[str] = []
    if set(components) != COMPONENT_ALLOW_LIST:
        reasons.append(MISSING_EVIDENCE)
    for component in components.values():
        if component.get("policy_hash") != request.get("policy_hash"):
            reasons.append(POLICY_MISMATCH)
        if component.get("tenant_hash") != request.get("tenant_hash"):
            reasons.append(TENANT_MISMATCH)
    evidence_aggregator = components.get("runtime_evidence_aggregator")
    replay_verifier = components.get("runtime_replay_verifier")
    approval_gate = components.get("runtime_approval_gate")
    if evidence_aggregator and evidence_aggregator.get("evidence_hash") != request.get("evidence_hash"):
        reasons.append(EVIDENCE_MISMATCH)
    if replay_verifier and replay_verifier.get("evidence_hash") != request.get("replay_hash"):
        reasons.append(REPLAY_MISMATCH)
    if approval_gate and approval_gate.get("evidence_hash") != request.get("approval_hash"):
        reasons.append(MISSING_APPROVAL)
    return tuple(reasons)


def _chronology_denials(components: Mapping[str, Mapping[str, Any]]) -> tuple[str, ...]:
    timestamps = [components[component]["timestamp"] for component in COMPONENT_ORDER if component in components]
    return () if timestamps == sorted(timestamps) else (INVALID_CHRONOLOGY,)


def _ready_decision(
    request: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
) -> RuntimeReleaseGateDecision:
    component_evidence_hashes = {component: components[component]["evidence_hash"] for component in COMPONENT_ORDER}
    payload = _decision_payload(request, component_evidence_hashes, RELEASE_READY_METADATA, ())
    return RuntimeReleaseGateDecision(
        adapter=ADAPTER_NAME,
        release_id_hash=_hash_text(request["release_id"]),
        release_readiness_hash=_canonical_hash(payload),
        policy_hash=request["policy_hash"],
        tenant_hash=request["tenant_hash"],
        evidence_hash=request["evidence_hash"],
        approval_hash=request["approval_hash"],
        replay_hash=request["replay_hash"],
        release_stage=request["release_stage"],
        component_order=COMPONENT_ORDER,
        component_evidence_hashes=component_evidence_hashes,
        readiness_state=RELEASE_READY_METADATA,
        denial_code=None,
        denial_reasons=(),
        schema_version=SUPPORTED_SCHEMA_VERSION,
        output_version=SUPPORTED_OUTPUT_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        hash_only=True,
        redacted=True,
        remaining_gaps=("release_metadata_does_not_authorize_execution", "human_review_required_before_release"),
    )


def _blocked_decision(
    request: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
    denial_reasons: tuple[str, ...],
) -> RuntimeReleaseGateDecision:
    component_evidence_hashes = {
        component: components[component].get("evidence_hash", _hash_text(f"missing:{component}"))
        for component in COMPONENT_ORDER
        if component in components
    }
    payload = _decision_payload(request, component_evidence_hashes, RELEASE_BLOCKED, denial_reasons)
    return RuntimeReleaseGateDecision(
        adapter=ADAPTER_NAME,
        release_id_hash=_hash_text(str(request.get("release_id"))) if isinstance(request.get("release_id"), str) else None,
        release_readiness_hash=_canonical_hash(payload),
        policy_hash=request.get("policy_hash") if isinstance(request.get("policy_hash"), str) and _HASH_RE.match(request["policy_hash"]) else None,
        tenant_hash=request.get("tenant_hash") if isinstance(request.get("tenant_hash"), str) and _HASH_RE.match(request["tenant_hash"]) else None,
        evidence_hash=request.get("evidence_hash") if isinstance(request.get("evidence_hash"), str) and _HASH_RE.match(request["evidence_hash"]) else None,
        approval_hash=request.get("approval_hash") if isinstance(request.get("approval_hash"), str) and _HASH_RE.match(request["approval_hash"]) else None,
        replay_hash=request.get("replay_hash") if isinstance(request.get("replay_hash"), str) and _HASH_RE.match(request["replay_hash"]) else None,
        release_stage=request.get("release_stage") if isinstance(request.get("release_stage"), str) else "BLOCKED",
        component_order=COMPONENT_ORDER,
        component_evidence_hashes=component_evidence_hashes,
        readiness_state=RELEASE_BLOCKED,
        denial_code=denial_reasons[0],
        denial_reasons=denial_reasons,
        schema_version=SUPPORTED_SCHEMA_VERSION,
        output_version=SUPPORTED_OUTPUT_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        hash_only=True,
        redacted=True,
        remaining_gaps=("release_gate_blocked_until_metadata_is_valid",),
    )


def _decision_payload(
    request: Mapping[str, Any],
    component_evidence_hashes: Mapping[str, str],
    readiness_state: str,
    denial_reasons: tuple[str, ...],
) -> Mapping[str, Any]:
    return {
        "adapter": ADAPTER_NAME,
        "release_id_hash": _hash_text(str(request.get("release_id", ""))),
        "policy_hash": request.get("policy_hash"),
        "tenant_hash": request.get("tenant_hash"),
        "evidence_hash": request.get("evidence_hash"),
        "approval_hash": request.get("approval_hash"),
        "replay_hash": request.get("replay_hash"),
        "release_stage": request.get("release_stage"),
        "component_order": COMPONENT_ORDER,
        "component_evidence_hashes": dict(component_evidence_hashes),
        "readiness_state": readiness_state,
        "denial_reasons": denial_reasons,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "hash_only": True,
        "redacted": True,
    }


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
