"""Deterministic Phase C Runtime Simulator metadata.

The simulator consumes Phase B release-gate metadata by hash/reference only and
produces local simulation readiness metadata. It never executes commands,
contacts providers, mutates policy, opens sockets, starts workers, or activates
production.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Mapping


SIMULATOR_NAME = "runtime_simulator"
SIM_READY = "SIM_READY"
SIM_BLOCKED = "SIM_BLOCKED"
SIM_REVIEW_REQUIRED = "SIM_REVIEW_REQUIRED"
SIM_FAILED_CLOSED = "SIM_FAILED_CLOSED"

SUPPORTED_SCHEMA_VERSION = "phase-c.runtime-simulator.v1"
SUPPORTED_SIMULATOR_VERSION = "phase-c.runtime-simulator-output.v1"
SUPPORTED_HASH_ALGORITHM = "sha256"
SUPPORTED_RELEASE_COMPONENT = "runtime_release_gate_adapter"
SUPPORTED_RELEASE_SCHEMA = "phase-b.runtime-release-gate-adapter.v1"
SUPPORTED_RELEASE_OUTPUT = "phase-b.release-readiness.v1"
SUPPORTED_RELEASE_STATE = "RELEASE_READY_METADATA"
SUPPORTED_SIMULATION_MODES = frozenset({"LOCAL_METADATA_ONLY", "GOVERNANCE_DRY_RUN"})

MISSING_METADATA = "MISSING_METADATA"
INVALID_SCHEMA = "INVALID_SCHEMA"
MISSING_PREDECESSOR_HASH = "MISSING_PREDECESSOR_HASH"
UNKNOWN_COMPONENT = "UNKNOWN_COMPONENT"
UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
CROSS_TENANT_METADATA = "CROSS_TENANT_METADATA"
POLICY_MISMATCH = "POLICY_MISMATCH"
APPROVAL_MISSING = "APPROVAL_MISSING"
MALFORMED_METADATA = "MALFORMED_METADATA"
UNKNOWN_METADATA = "UNKNOWN_METADATA"
INVALID_HASH = "INVALID_HASH"
UNSUPPORTED_HASH_ALGORITHM = "UNSUPPORTED_HASH_ALGORITHM"
NON_HASH_ONLY_EVIDENCE = "NON_HASH_ONLY_EVIDENCE"
UNREDACTED_EVIDENCE = "UNREDACTED_EVIDENCE"
EXECUTION_FLAG_ENABLED = "EXECUTION_FLAG_ENABLED"
PROVIDER_EXECUTION_ENABLED = "PROVIDER_EXECUTION_ENABLED"
PRODUCTION_ACTIVATION_ENABLED = "PRODUCTION_ACTIVATION_ENABLED"
SENSITIVE_DATA_PRESENT = "SENSITIVE_DATA_PRESENT"

DENIAL_CODES = (
    MISSING_METADATA,
    INVALID_SCHEMA,
    MISSING_PREDECESSOR_HASH,
    UNKNOWN_COMPONENT,
    UNSUPPORTED_VERSION,
    CROSS_TENANT_METADATA,
    POLICY_MISMATCH,
    APPROVAL_MISSING,
    MALFORMED_METADATA,
    UNKNOWN_METADATA,
    INVALID_HASH,
    UNSUPPORTED_HASH_ALGORITHM,
    NON_HASH_ONLY_EVIDENCE,
    UNREDACTED_EVIDENCE,
    EXECUTION_FLAG_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    PRODUCTION_ACTIVATION_ENABLED,
    SENSITIVE_DATA_PRESENT,
)

REQUIRED_REQUEST_FIELDS = frozenset({
    "simulation_id",
    "policy_hash",
    "tenant_hash",
    "evidence_hash",
    "release_readiness_hash",
    "approval_hash",
    "simulation_mode",
    "schema_version",
    "simulator_version",
    "hash_algorithm",
    "release_metadata",
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "hash_only",
    "redacted",
})

REQUIRED_RELEASE_FIELDS = frozenset({
    "component",
    "release_readiness_hash",
    "policy_hash",
    "tenant_hash",
    "evidence_hash",
    "approval_hash",
    "replay_hash",
    "readiness_state",
    "schema_version",
    "output_version",
    "hash_algorithm",
    "hash_only",
    "redacted",
    "execution_allowed",
    "provider_execution",
    "production_activation",
})

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^sim-[a-z0-9][a-z0-9-]{2,80}$")
_SENSITIVE_KEYS = frozenset({
    "api_key",
    "body",
    "command",
    "content",
    "credential",
    "credentials",
    "password",
    "payload",
    "private_key",
    "prompt",
    "raw",
    "raw_payload",
    "secret",
    "sensitive",
    "token",
})


@dataclass(frozen=True)
class RuntimeSimulatorRequest:
    simulation_id: str
    policy_hash: str
    tenant_hash: str
    evidence_hash: str
    release_readiness_hash: str
    approval_hash: str
    simulation_mode: str
    schema_version: str
    simulator_version: str
    hash_algorithm: str
    release_metadata: Mapping[str, Any]
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    hash_only: bool = True
    redacted: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "evidence_hash": self.evidence_hash,
            "release_readiness_hash": self.release_readiness_hash,
            "approval_hash": self.approval_hash,
            "simulation_mode": self.simulation_mode,
            "schema_version": self.schema_version,
            "simulator_version": self.simulator_version,
            "hash_algorithm": self.hash_algorithm,
            "release_metadata": dict(self.release_metadata),
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
        }


@dataclass(frozen=True)
class RuntimeSimulatorDecision:
    simulator: str
    simulation_id_hash: str | None
    simulation_hash: str
    policy_hash: str | None
    tenant_hash: str | None
    evidence_hash: str | None
    release_readiness_hash: str | None
    approval_hash: str | None
    simulation_mode: str
    simulation_state: str
    denial_code: str | None
    denial_reasons: tuple[str, ...]
    schema_version: str
    simulator_version: str
    hash_algorithm: str
    execution_allowed: bool
    provider_execution: bool
    production_activation: bool
    hash_only: bool
    redacted: bool
    remaining_gaps: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "simulator": self.simulator,
            "simulation_id_hash": self.simulation_id_hash,
            "simulation_hash": self.simulation_hash,
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "evidence_hash": self.evidence_hash,
            "release_readiness_hash": self.release_readiness_hash,
            "approval_hash": self.approval_hash,
            "simulation_mode": self.simulation_mode,
            "simulation_state": self.simulation_state,
            "denial_code": self.denial_code,
            "denial_reasons": self.denial_reasons,
            "schema_version": self.schema_version,
            "simulator_version": self.simulator_version,
            "hash_algorithm": self.hash_algorithm,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
            "remaining_gaps": self.remaining_gaps,
        }


def simulate_runtime(request: RuntimeSimulatorRequest | Mapping[str, Any]) -> RuntimeSimulatorDecision:
    """Return deterministic Phase C simulation metadata without execution."""

    payload, request_reasons = _request_payload(request)
    release_metadata, release_reasons = _release_payload(payload.get("release_metadata"))
    reasons = list(request_reasons)
    reasons.extend(release_reasons)
    reasons.extend(_request_denials(payload))
    reasons.extend(_release_denials(payload, release_metadata))
    denial_reasons = tuple(sorted(set(reasons)))
    if SENSITIVE_DATA_PRESENT in denial_reasons or MALFORMED_METADATA in denial_reasons and not payload:
        return _decision(payload, release_metadata, SIM_FAILED_CLOSED, denial_reasons)
    if APPROVAL_MISSING in denial_reasons and set(denial_reasons).issubset({APPROVAL_MISSING}):
        return _decision(payload, release_metadata, SIM_REVIEW_REQUIRED, denial_reasons)
    if denial_reasons:
        return _decision(payload, release_metadata, SIM_BLOCKED, denial_reasons)
    return _decision(payload, release_metadata, SIM_READY, ())


def _request_payload(request: RuntimeSimulatorRequest | Mapping[str, Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
    if isinstance(request, RuntimeSimulatorRequest):
        payload = request.as_dict()
    elif isinstance(request, Mapping):
        payload = dict(request)
    else:
        return {}, (MALFORMED_METADATA,)
    reasons: list[str] = []
    if REQUIRED_REQUEST_FIELDS.difference(payload):
        reasons.append(MISSING_METADATA)
    if set(payload).difference(REQUIRED_REQUEST_FIELDS):
        reasons.append(UNKNOWN_METADATA)
    if _contains_sensitive_data(payload):
        reasons.append(SENSITIVE_DATA_PRESENT)
    return payload, tuple(reasons)


def _release_payload(value: Any) -> tuple[dict[str, Any], tuple[str, ...]]:
    if not isinstance(value, Mapping):
        return {}, (MISSING_METADATA,)
    payload = dict(value)
    reasons: list[str] = []
    if REQUIRED_RELEASE_FIELDS.difference(payload):
        reasons.append(MISSING_METADATA)
    if set(payload).difference(REQUIRED_RELEASE_FIELDS):
        reasons.append(UNKNOWN_METADATA)
    if _contains_sensitive_data(payload):
        reasons.append(SENSITIVE_DATA_PRESENT)
    return payload, tuple(reasons)


def _request_denials(payload: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    simulation_id = payload.get("simulation_id")
    if not isinstance(simulation_id, str) or not _ID_RE.match(simulation_id):
        reasons.append(MALFORMED_METADATA)
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        reasons.append(INVALID_SCHEMA)
    if payload.get("simulator_version") != SUPPORTED_SIMULATOR_VERSION:
        reasons.append(UNSUPPORTED_VERSION)
    if payload.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(UNSUPPORTED_HASH_ALGORITHM)
    if payload.get("simulation_mode") not in SUPPORTED_SIMULATION_MODES:
        reasons.append(MALFORMED_METADATA)
    for field in ("policy_hash", "tenant_hash", "evidence_hash", "release_readiness_hash"):
        if not payload.get(field):
            reasons.append(MISSING_PREDECESSOR_HASH if field == "release_readiness_hash" else MISSING_METADATA)
        elif isinstance(payload.get(field), str) and not _HASH_RE.match(payload[field]):
            reasons.append(INVALID_HASH)
    if payload.get("approval_hash") and isinstance(payload.get("approval_hash"), str) and not _HASH_RE.match(payload["approval_hash"]):
        reasons.append(INVALID_HASH)
    if not payload.get("approval_hash"):
        reasons.append(APPROVAL_MISSING)
    reasons.extend(_flag_denials(payload))
    return tuple(reasons)


def _release_denials(request: Mapping[str, Any], release: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    if not release:
        return (MISSING_METADATA,)
    if release.get("component") != SUPPORTED_RELEASE_COMPONENT:
        reasons.append(UNKNOWN_COMPONENT)
    if release.get("schema_version") != SUPPORTED_RELEASE_SCHEMA:
        reasons.append(INVALID_SCHEMA)
    if release.get("output_version") != SUPPORTED_RELEASE_OUTPUT:
        reasons.append(UNSUPPORTED_VERSION)
    if release.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(UNSUPPORTED_HASH_ALGORITHM)
    if release.get("readiness_state") != SUPPORTED_RELEASE_STATE:
        reasons.append(MISSING_PREDECESSOR_HASH)
    for field in ("policy_hash", "tenant_hash", "evidence_hash", "release_readiness_hash", "replay_hash"):
        if not release.get(field):
            reasons.append(MISSING_PREDECESSOR_HASH if field == "release_readiness_hash" else MISSING_METADATA)
        elif isinstance(release.get(field), str) and not _HASH_RE.match(release[field]):
            reasons.append(INVALID_HASH)
    if release.get("approval_hash") and isinstance(release.get("approval_hash"), str) and not _HASH_RE.match(release["approval_hash"]):
        reasons.append(INVALID_HASH)
    if not release.get("approval_hash"):
        reasons.append(APPROVAL_MISSING)
    if release.get("policy_hash") != request.get("policy_hash"):
        reasons.append(POLICY_MISMATCH)
    if release.get("tenant_hash") != request.get("tenant_hash"):
        reasons.append(CROSS_TENANT_METADATA)
    if release.get("evidence_hash") != request.get("evidence_hash"):
        reasons.append(MISSING_PREDECESSOR_HASH)
    if release.get("release_readiness_hash") != request.get("release_readiness_hash"):
        reasons.append(MISSING_PREDECESSOR_HASH)
    if release.get("approval_hash") and request.get("approval_hash") and release.get("approval_hash") != request.get("approval_hash"):
        reasons.append(APPROVAL_MISSING)
    reasons.extend(_flag_denials(release))
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


def _decision(
    request: Mapping[str, Any],
    release: Mapping[str, Any],
    state: str,
    denial_reasons: tuple[str, ...],
) -> RuntimeSimulatorDecision:
    payload = {
        "simulator": SIMULATOR_NAME,
        "simulation_id_hash": _hash_text(str(request.get("simulation_id", ""))),
        "policy_hash": request.get("policy_hash"),
        "tenant_hash": request.get("tenant_hash"),
        "evidence_hash": request.get("evidence_hash"),
        "release_readiness_hash": request.get("release_readiness_hash"),
        "approval_hash": request.get("approval_hash"),
        "simulation_mode": request.get("simulation_mode"),
        "release_component": release.get("component"),
        "release_state": release.get("readiness_state"),
        "simulation_state": state,
        "denial_reasons": denial_reasons,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "hash_only": True,
        "redacted": True,
    }
    return RuntimeSimulatorDecision(
        simulator=SIMULATOR_NAME,
        simulation_id_hash=_hash_text(str(request.get("simulation_id"))) if isinstance(request.get("simulation_id"), str) else None,
        simulation_hash=_canonical_hash(payload),
        policy_hash=_valid_hash_or_none(request.get("policy_hash")),
        tenant_hash=_valid_hash_or_none(request.get("tenant_hash")),
        evidence_hash=_valid_hash_or_none(request.get("evidence_hash")),
        release_readiness_hash=_valid_hash_or_none(request.get("release_readiness_hash")),
        approval_hash=_valid_hash_or_none(request.get("approval_hash")),
        simulation_mode=request.get("simulation_mode") if isinstance(request.get("simulation_mode"), str) else "BLOCKED",
        simulation_state=state,
        denial_code=denial_reasons[0] if denial_reasons else None,
        denial_reasons=denial_reasons,
        schema_version=SUPPORTED_SCHEMA_VERSION,
        simulator_version=SUPPORTED_SIMULATOR_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        hash_only=True,
        redacted=True,
        remaining_gaps=_remaining_gaps(state),
    )


def _remaining_gaps(state: str) -> tuple[str, ...]:
    if state == SIM_READY:
        return ("simulation_metadata_does_not_authorize_execution", "human_approval_required_before_any_sandbox_action")
    if state == SIM_REVIEW_REQUIRED:
        return ("simulation_requires_external_human_approval_reference",)
    return ("simulation_blocked_until_metadata_is_valid",)


def _valid_hash_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and _HASH_RE.match(value) else None


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
