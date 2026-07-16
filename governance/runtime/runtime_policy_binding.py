"""Deterministic Runtime Policy Binding metadata.

The binding verifies that approved Phase B runtime evidence references share one
policy, tenant, runtime version, and decision chain. It never executes runtime
actions, opens sockets, starts processes, calls providers, or activates
production behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Mapping, Sequence


BINDING_NAME = "runtime_policy_binding"
POLICY_BOUND = "POLICY_BOUND"
POLICY_BLOCKED = "POLICY_BLOCKED"
SUPPORTED_SCHEMA_VERSION = "phase-b.runtime-policy-binding.v1"
SUPPORTED_RUNTIME_VERSION = "phase-b.runtime.v1"
SUPPORTED_HASH_ALGORITHM = "sha256"
GENESIS_DECISION_HASH = "sha256:" + ("0" * 64)

COMPONENT_ORDER = (
    "agent_runtime",
    "runtime_coordinator",
    "runtime_health",
    "event_bus",
    "execution_scheduler",
    "runtime_evidence_aggregator",
)
COMPONENT_ALLOW_LIST = frozenset(COMPONENT_ORDER)

MISSING_DEPENDENCY = "MISSING_DEPENDENCY"
UNKNOWN_COMPONENT = "UNKNOWN_COMPONENT"
DUPLICATE_EVIDENCE = "DUPLICATE_EVIDENCE"
MISSING_HASH = "MISSING_HASH"
INVALID_HASH = "INVALID_HASH"
POLICY_HASH_MISMATCH = "POLICY_HASH_MISMATCH"
EVIDENCE_HASH_MISMATCH = "EVIDENCE_HASH_MISMATCH"
TENANT_HASH_MISMATCH = "TENANT_HASH_MISMATCH"
DECISION_CONTINUITY_MISMATCH = "DECISION_CONTINUITY_MISMATCH"
UNKNOWN_SCHEMA = "UNKNOWN_SCHEMA"
RUNTIME_VERSION_MISMATCH = "RUNTIME_VERSION_MISMATCH"
MALFORMED_METADATA = "MALFORMED_METADATA"
INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
ORDERING_MISMATCH = "ORDERING_MISMATCH"
NON_HASH_ONLY_EVIDENCE = "NON_HASH_ONLY_EVIDENCE"
UNREDACTED_EVIDENCE = "UNREDACTED_EVIDENCE"
EXECUTION_FLAG_ENABLED = "EXECUTION_FLAG_ENABLED"
PROVIDER_EXECUTION_ENABLED = "PROVIDER_EXECUTION_ENABLED"
PRODUCTION_ACTIVATION_ENABLED = "PRODUCTION_ACTIVATION_ENABLED"
RAW_PAYLOAD_PRESENT = "RAW_PAYLOAD_PRESENT"
SENSITIVE_DATA_PRESENT = "SENSITIVE_DATA_PRESENT"

DENIAL_CODES = (
    MISSING_DEPENDENCY,
    UNKNOWN_COMPONENT,
    DUPLICATE_EVIDENCE,
    MISSING_HASH,
    INVALID_HASH,
    POLICY_HASH_MISMATCH,
    EVIDENCE_HASH_MISMATCH,
    TENANT_HASH_MISMATCH,
    DECISION_CONTINUITY_MISMATCH,
    UNKNOWN_SCHEMA,
    RUNTIME_VERSION_MISMATCH,
    MALFORMED_METADATA,
    INVALID_FIELD_TYPE,
    ORDERING_MISMATCH,
    NON_HASH_ONLY_EVIDENCE,
    UNREDACTED_EVIDENCE,
    EXECUTION_FLAG_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    PRODUCTION_ACTIVATION_ENABLED,
    RAW_PAYLOAD_PRESENT,
    SENSITIVE_DATA_PRESENT,
)

REQUIRED_FIELDS = frozenset({
    "component",
    "evidence_hash",
    "policy_hash",
    "tenant_hash",
    "decision_hash",
    "previous_decision_hash",
    "schema_version",
    "runtime_version",
    "hash_algorithm",
    "hash_only",
    "redacted",
    "execution_allowed",
    "provider_execution",
    "production_activation",
})

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SENSITIVE_KEYS = frozenset({
    "api_key",
    "body",
    "content",
    "credential",
    "credentials",
    "customer_data",
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
class RuntimePolicyEvidenceReference:
    component: str
    evidence_hash: str
    policy_hash: str
    tenant_hash: str
    decision_hash: str
    previous_decision_hash: str
    schema_version: str = SUPPORTED_SCHEMA_VERSION
    runtime_version: str = SUPPORTED_RUNTIME_VERSION
    hash_algorithm: str = SUPPORTED_HASH_ALGORITHM
    hash_only: bool = True
    redacted: bool = True
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
            "previous_decision_hash": self.previous_decision_hash,
            "schema_version": self.schema_version,
            "runtime_version": self.runtime_version,
            "hash_algorithm": self.hash_algorithm,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
        }


@dataclass(frozen=True)
class RuntimePolicyBindingRequest:
    policy_hash: str
    tenant_hash: str
    evidence_hash: str
    runtime_version: str
    references: Sequence[RuntimePolicyEvidenceReference | Mapping[str, Any]]


@dataclass(frozen=True)
class RuntimePolicyBindingDecision:
    binding: str
    binding_hash: str
    policy_hash: str | None
    tenant_hash: str | None
    evidence_hash: str | None
    runtime_version: str
    component_order: tuple[str, ...]
    component_evidence_hashes: Mapping[str, str]
    decision_chain_hash: str
    schema_version: str
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
            "binding": self.binding,
            "binding_hash": self.binding_hash,
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "evidence_hash": self.evidence_hash,
            "runtime_version": self.runtime_version,
            "component_order": self.component_order,
            "component_evidence_hashes": dict(self.component_evidence_hashes),
            "decision_chain_hash": self.decision_chain_hash,
            "schema_version": self.schema_version,
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


def bind_runtime_policy(request: RuntimePolicyBindingRequest) -> RuntimePolicyBindingDecision:
    """Verify deterministic policy binding metadata for Phase B runtime evidence."""

    normalized, reasons = _normalize_references(request.references)
    reasons.extend(_request_denials(request))
    reasons.extend(_collection_denials(request, normalized))
    if not reasons:
        reasons.extend(_ordering_denials(normalized))
        reasons.extend(_decision_chain_denials(normalized))
    denial_reasons = tuple(sorted(set(reasons)))
    if denial_reasons:
        return _blocked_decision(request, normalized, denial_reasons)
    return _bound_decision(request, normalized)


def _normalize_references(
    references: Sequence[RuntimePolicyEvidenceReference | Mapping[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    normalized: dict[str, dict[str, Any]] = {}
    reasons: list[str] = []
    seen: set[str] = set()
    if not isinstance(references, Sequence) or isinstance(references, (str, bytes)):
        return {}, [MALFORMED_METADATA]
    for reference in references:
        if isinstance(reference, RuntimePolicyEvidenceReference):
            payload = reference.as_dict()
        elif isinstance(reference, Mapping):
            payload = dict(reference)
        else:
            reasons.append(MALFORMED_METADATA)
            continue
        if _contains_raw_payload(payload):
            reasons.append(RAW_PAYLOAD_PRESENT)
        if _contains_sensitive_data(payload):
            reasons.append(SENSITIVE_DATA_PRESENT)
        missing = REQUIRED_FIELDS.difference(payload)
        if missing:
            reasons.append(MISSING_DEPENDENCY)
        component = payload.get("component")
        if not isinstance(component, str):
            reasons.append(INVALID_FIELD_TYPE)
            continue
        if component in seen:
            reasons.append(DUPLICATE_EVIDENCE)
        seen.add(component)
        if component not in COMPONENT_ALLOW_LIST:
            reasons.append(UNKNOWN_COMPONENT)
        reasons.extend(_field_denials(payload))
        if component in COMPONENT_ALLOW_LIST and component not in normalized:
            normalized[component] = payload
    return normalized, reasons


def _request_denials(request: RuntimePolicyBindingRequest) -> tuple[str, ...]:
    reasons: list[str] = []
    for value in (request.policy_hash, request.tenant_hash, request.evidence_hash):
        if not value:
            reasons.append(MISSING_HASH)
        elif not _HASH_RE.match(value):
            reasons.append(INVALID_HASH)
    if request.runtime_version != SUPPORTED_RUNTIME_VERSION:
        reasons.append(RUNTIME_VERSION_MISMATCH)
    return tuple(reasons)


def _field_denials(payload: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in payload:
            continue
        value = payload[field]
        if field in {"component", "evidence_hash", "policy_hash", "tenant_hash", "decision_hash", "previous_decision_hash", "schema_version", "runtime_version", "hash_algorithm"} and not isinstance(value, str):
            reasons.append(INVALID_FIELD_TYPE)
        if field in {"hash_only", "redacted", "execution_allowed", "provider_execution", "production_activation"} and not isinstance(value, bool):
            reasons.append(INVALID_FIELD_TYPE)
    for field in ("evidence_hash", "policy_hash", "tenant_hash", "decision_hash", "previous_decision_hash"):
        value = payload.get(field)
        if not value:
            reasons.append(MISSING_HASH)
        elif isinstance(value, str) and not _HASH_RE.match(value):
            reasons.append(INVALID_HASH)
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        reasons.append(UNKNOWN_SCHEMA)
    if payload.get("runtime_version") != SUPPORTED_RUNTIME_VERSION:
        reasons.append(RUNTIME_VERSION_MISMATCH)
    if payload.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(MALFORMED_METADATA)
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


def _collection_denials(
    request: RuntimePolicyBindingRequest,
    normalized: Mapping[str, Mapping[str, Any]],
) -> tuple[str, ...]:
    reasons: list[str] = []
    if set(normalized) != COMPONENT_ALLOW_LIST:
        reasons.append(MISSING_DEPENDENCY)
    policy_hashes = {payload.get("policy_hash") for payload in normalized.values()}
    tenant_hashes = {payload.get("tenant_hash") for payload in normalized.values()}
    runtime_versions = {payload.get("runtime_version") for payload in normalized.values()}
    if len(policy_hashes) > 1 or (policy_hashes and request.policy_hash not in policy_hashes):
        reasons.append(POLICY_HASH_MISMATCH)
    if len(tenant_hashes) > 1 or (tenant_hashes and request.tenant_hash not in tenant_hashes):
        reasons.append(TENANT_HASH_MISMATCH)
    if len(runtime_versions) > 1 or (runtime_versions and request.runtime_version not in runtime_versions):
        reasons.append(RUNTIME_VERSION_MISMATCH)
    aggregator = normalized.get("runtime_evidence_aggregator")
    if aggregator and aggregator.get("evidence_hash") != request.evidence_hash:
        reasons.append(EVIDENCE_HASH_MISMATCH)
    return tuple(reasons)


def _ordering_denials(normalized: Mapping[str, Mapping[str, Any]]) -> tuple[str, ...]:
    ordered_components = tuple(component for component in COMPONENT_ORDER if component in normalized)
    return () if ordered_components == COMPONENT_ORDER else (ORDERING_MISMATCH,)


def _decision_chain_denials(normalized: Mapping[str, Mapping[str, Any]]) -> tuple[str, ...]:
    previous = GENESIS_DECISION_HASH
    for component in COMPONENT_ORDER:
        payload = normalized[component]
        if payload["previous_decision_hash"] != previous:
            return (DECISION_CONTINUITY_MISMATCH,)
        previous = payload["decision_hash"]
    return ()


def _bound_decision(
    request: RuntimePolicyBindingRequest,
    normalized: Mapping[str, Mapping[str, Any]],
) -> RuntimePolicyBindingDecision:
    component_evidence_hashes = {
        component: normalized[component]["evidence_hash"] for component in COMPONENT_ORDER
    }
    decision_chain = tuple(
        (component, normalized[component]["previous_decision_hash"], normalized[component]["decision_hash"])
        for component in COMPONENT_ORDER
    )
    decision_chain_hash = _canonical_hash({"decision_chain": decision_chain})
    payload = {
        "binding": BINDING_NAME,
        "policy_hash": request.policy_hash,
        "tenant_hash": request.tenant_hash,
        "evidence_hash": request.evidence_hash,
        "runtime_version": request.runtime_version,
        "component_order": COMPONENT_ORDER,
        "component_evidence_hashes": component_evidence_hashes,
        "decision_chain_hash": decision_chain_hash,
        "schema_version": SUPPORTED_SCHEMA_VERSION,
        "hash_algorithm": SUPPORTED_HASH_ALGORITHM,
        "hash_only": True,
        "redacted": True,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "status": POLICY_BOUND,
    }
    return RuntimePolicyBindingDecision(
        binding=BINDING_NAME,
        binding_hash=_canonical_hash(payload),
        policy_hash=request.policy_hash,
        tenant_hash=request.tenant_hash,
        evidence_hash=request.evidence_hash,
        runtime_version=request.runtime_version,
        component_order=COMPONENT_ORDER,
        component_evidence_hashes=component_evidence_hashes,
        decision_chain_hash=decision_chain_hash,
        schema_version=SUPPORTED_SCHEMA_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        hash_only=True,
        redacted=True,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        status=POLICY_BOUND,
        denial_code=None,
        denial_reasons=(),
        remaining_gaps=("human_approval_remains_external", "binding_does_not_authorize_execution"),
    )


def _blocked_decision(
    request: RuntimePolicyBindingRequest,
    normalized: Mapping[str, Mapping[str, Any]],
    denial_reasons: tuple[str, ...],
) -> RuntimePolicyBindingDecision:
    component_evidence_hashes = {
        component: normalized[component].get("evidence_hash", _hash_text(f"missing:{component}"))
        for component in COMPONENT_ORDER
        if component in normalized
    }
    decision_chain_hash = _canonical_hash({
        "blocked_components": component_evidence_hashes,
        "denial_reasons": denial_reasons,
    })
    payload = {
        "binding": BINDING_NAME,
        "component_order": COMPONENT_ORDER,
        "component_evidence_hashes": component_evidence_hashes,
        "decision_chain_hash": decision_chain_hash,
        "denial_reasons": denial_reasons,
        "status": POLICY_BLOCKED,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "hash_only": True,
        "redacted": True,
    }
    return RuntimePolicyBindingDecision(
        binding=BINDING_NAME,
        binding_hash=_canonical_hash(payload),
        policy_hash=request.policy_hash if _HASH_RE.match(request.policy_hash or "") else None,
        tenant_hash=request.tenant_hash if _HASH_RE.match(request.tenant_hash or "") else None,
        evidence_hash=request.evidence_hash if _HASH_RE.match(request.evidence_hash or "") else None,
        runtime_version=request.runtime_version,
        component_order=COMPONENT_ORDER,
        component_evidence_hashes=component_evidence_hashes,
        decision_chain_hash=decision_chain_hash,
        schema_version=SUPPORTED_SCHEMA_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        hash_only=True,
        redacted=True,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        status=POLICY_BLOCKED,
        denial_code=denial_reasons[0],
        denial_reasons=denial_reasons,
        remaining_gaps=("binding_blocked_until_metadata_is_valid",),
    )


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
