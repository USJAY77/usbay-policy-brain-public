"""Deterministic PB-C2 Human Approval Gateway metadata.

The gateway validates external human approval references for PB-C1 simulator
metadata. It never approves execution, contacts providers, opens sockets,
spawns work, mutates policy, deploys, or activates production.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any, Mapping, Sequence


GATEWAY_NAME = "human_approval_gateway"
APPROVAL_VALID = "APPROVAL_VALID"
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
APPROVAL_BLOCKED = "APPROVAL_BLOCKED"
APPROVAL_FAILED_CLOSED = "APPROVAL_FAILED_CLOSED"

SUPPORTED_SCHEMA_VERSION = "phase-c.human-approval-gateway.v1"
SUPPORTED_OUTPUT_VERSION = "phase-c.human-approval-gateway-output.v1"
SUPPORTED_APPROVAL_SCHEMA = "phase-c.human-approval-reference.v1"
SUPPORTED_APPROVAL_OUTPUT = "phase-c.human-approval-reference-output.v1"
SUPPORTED_SIMULATOR_SCHEMA = "phase-c.runtime-simulator.v1"
SUPPORTED_SIMULATOR_OUTPUT = "phase-c.runtime-simulator-output.v1"
SUPPORTED_HASH_ALGORITHM = "sha256"
SUPPORTED_APPROVAL_COMPONENT = "human_approval_reference"
SUPPORTED_SIMULATOR_COMPONENT = "runtime_simulator"
SUPPORTED_SIMULATOR_STATE = "SIM_READY"
SUPPORTED_APPROVAL_STATUSES = frozenset({"APPROVED", "PENDING", "REJECTED", "EXPIRED"})
FUTURE_TIMESTAMP_TOLERANCE_SECONDS = 300

MISSING_APPROVAL_REFERENCE = "MISSING_APPROVAL_REFERENCE"
MISSING_APPROVAL_HASH = "MISSING_APPROVAL_HASH"
MISSING_SIMULATOR_REFERENCE = "MISSING_SIMULATOR_REFERENCE"
MISSING_SIMULATOR_HASH = "MISSING_SIMULATOR_HASH"
APPROVAL_NOT_GRANTED = "APPROVAL_NOT_GRANTED"
WRONG_APPROVER_ROLE = "WRONG_APPROVER_ROLE"
WRONG_APPROVAL_SCOPE = "WRONG_APPROVAL_SCOPE"
APPROVAL_EXPIRED_REASON = "APPROVAL_EXPIRED"
APPROVAL_TIMESTAMP_IN_FUTURE = "APPROVAL_TIMESTAMP_IN_FUTURE"
TENANT_MISMATCH = "TENANT_MISMATCH"
POLICY_MISMATCH = "POLICY_MISMATCH"
EVIDENCE_MISMATCH = "EVIDENCE_MISMATCH"
SIMULATOR_HASH_MISMATCH = "SIMULATOR_HASH_MISMATCH"
DUPLICATE_APPROVAL_REFERENCE = "DUPLICATE_APPROVAL_REFERENCE"
REPLAYED_APPROVAL_REFERENCE = "REPLAYED_APPROVAL_REFERENCE"
MALFORMED_METADATA = "MALFORMED_METADATA"
UNKNOWN_METADATA = "UNKNOWN_METADATA"
UNKNOWN_COMPONENT = "UNKNOWN_COMPONENT"
UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
UNSUPPORTED_HASH_ALGORITHM = "UNSUPPORTED_HASH_ALGORITHM"
INVALID_HASH = "INVALID_HASH"
NON_HASH_ONLY_EVIDENCE = "NON_HASH_ONLY_EVIDENCE"
UNREDACTED_EVIDENCE = "UNREDACTED_EVIDENCE"
RAW_APPROVAL_CONTENT = "RAW_APPROVAL_CONTENT"
EXECUTION_FLAG_ENABLED = "EXECUTION_FLAG_ENABLED"
PROVIDER_EXECUTION_ENABLED = "PROVIDER_EXECUTION_ENABLED"
PRODUCTION_ACTIVATION_ENABLED = "PRODUCTION_ACTIVATION_ENABLED"
RUNTIME_EXECUTION_ENABLED = "RUNTIME_EXECUTION_ENABLED"
DEPLOYMENT_EXECUTION_ENABLED = "DEPLOYMENT_EXECUTION_ENABLED"
POLICY_MUTATION_ENABLED = "POLICY_MUTATION_ENABLED"
NETWORK_ACCESS_ENABLED = "NETWORK_ACCESS_ENABLED"

DENIAL_CODES = (
    MISSING_APPROVAL_REFERENCE,
    MISSING_APPROVAL_HASH,
    MISSING_SIMULATOR_REFERENCE,
    MISSING_SIMULATOR_HASH,
    APPROVAL_NOT_GRANTED,
    WRONG_APPROVER_ROLE,
    WRONG_APPROVAL_SCOPE,
    APPROVAL_EXPIRED_REASON,
    APPROVAL_TIMESTAMP_IN_FUTURE,
    TENANT_MISMATCH,
    POLICY_MISMATCH,
    EVIDENCE_MISMATCH,
    SIMULATOR_HASH_MISMATCH,
    DUPLICATE_APPROVAL_REFERENCE,
    REPLAYED_APPROVAL_REFERENCE,
    MALFORMED_METADATA,
    UNKNOWN_METADATA,
    UNKNOWN_COMPONENT,
    UNSUPPORTED_SCHEMA,
    UNSUPPORTED_VERSION,
    UNSUPPORTED_HASH_ALGORITHM,
    INVALID_HASH,
    NON_HASH_ONLY_EVIDENCE,
    UNREDACTED_EVIDENCE,
    RAW_APPROVAL_CONTENT,
    EXECUTION_FLAG_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    PRODUCTION_ACTIVATION_ENABLED,
    RUNTIME_EXECUTION_ENABLED,
    DEPLOYMENT_EXECUTION_ENABLED,
    POLICY_MUTATION_ENABLED,
    NETWORK_ACCESS_ENABLED,
)

REQUIRED_REQUEST_FIELDS = frozenset({
    "gateway_id",
    "policy_hash",
    "tenant_hash",
    "evidence_hash",
    "simulator_decision_hash",
    "approval_reference",
    "approval_hash",
    "approver_role_hash",
    "scope_hash",
    "as_of",
    "schema_version",
    "output_version",
    "hash_algorithm",
    "simulator_metadata",
    "approval_metadata",
    "prior_approval_hashes",
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "runtime_execution",
    "deployment_execution",
    "policy_mutation",
    "network_access",
    "hash_only",
    "redacted",
})

REQUIRED_APPROVAL_FIELDS = frozenset({
    "component",
    "schema_version",
    "output_version",
    "approval_reference",
    "approval_hash",
    "approval_status",
    "approver_role_hash",
    "scope_hash",
    "tenant_hash",
    "policy_hash",
    "evidence_hash",
    "simulator_decision_hash",
    "issued_at",
    "expires_at",
    "hash_algorithm",
})

REQUIRED_SIMULATOR_FIELDS = frozenset({
    "component",
    "schema_version",
    "output_version",
    "simulation_hash",
    "simulation_state",
    "policy_hash",
    "tenant_hash",
    "evidence_hash",
    "hash_algorithm",
    "hash_only",
    "redacted",
    "execution_allowed",
    "provider_execution",
    "production_activation",
})

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^approval-gateway-[a-z0-9][a-z0-9-]{2,80}$")
_REFERENCE_RE = re.compile(r"^approval-ref-[a-z0-9][a-z0-9-]{2,80}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RAW_APPROVAL_KEYS = frozenset({
    "api_key",
    "body",
    "comment",
    "comments",
    "content",
    "credential",
    "credentials",
    "customer",
    "customer_data",
    "email",
    "free_form",
    "freeform",
    "identity_signature",
    "name",
    "payload",
    "policy_payload",
    "private_key",
    "raw",
    "raw_approval",
    "raw_payload",
    "secret",
    "signature",
    "text",
    "token",
})


@dataclass(frozen=True)
class HumanApprovalGatewayRequest:
    gateway_id: str
    policy_hash: str
    tenant_hash: str
    evidence_hash: str
    simulator_decision_hash: str
    approval_reference: str
    approval_hash: str
    approver_role_hash: str
    scope_hash: str
    as_of: str
    schema_version: str
    output_version: str
    hash_algorithm: str
    simulator_metadata: Mapping[str, Any]
    approval_metadata: Mapping[str, Any]
    prior_approval_hashes: Sequence[str] = ()
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    runtime_execution: bool = False
    deployment_execution: bool = False
    policy_mutation: bool = False
    network_access: bool = False
    hash_only: bool = True
    redacted: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "gateway_id": self.gateway_id,
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "evidence_hash": self.evidence_hash,
            "simulator_decision_hash": self.simulator_decision_hash,
            "approval_reference": self.approval_reference,
            "approval_hash": self.approval_hash,
            "approver_role_hash": self.approver_role_hash,
            "scope_hash": self.scope_hash,
            "as_of": self.as_of,
            "schema_version": self.schema_version,
            "output_version": self.output_version,
            "hash_algorithm": self.hash_algorithm,
            "simulator_metadata": dict(self.simulator_metadata),
            "approval_metadata": dict(self.approval_metadata),
            "prior_approval_hashes": tuple(self.prior_approval_hashes),
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "runtime_execution": self.runtime_execution,
            "deployment_execution": self.deployment_execution,
            "policy_mutation": self.policy_mutation,
            "network_access": self.network_access,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
        }


@dataclass(frozen=True)
class HumanApprovalGatewayDecision:
    gateway: str
    gateway_id_hash: str | None
    approval_gateway_hash: str
    policy_hash: str | None
    tenant_hash: str | None
    evidence_hash: str | None
    simulator_decision_hash: str | None
    approval_hash: str | None
    approval_reference_hash: str | None
    approver_role_hash: str | None
    scope_hash: str | None
    approval_state: str
    denial_code: str | None
    denial_reasons: tuple[str, ...]
    schema_version: str
    output_version: str
    hash_algorithm: str
    execution_allowed: bool
    provider_execution: bool
    production_activation: bool
    runtime_execution: bool
    deployment_execution: bool
    policy_mutation: bool
    network_access: bool
    hash_only: bool
    redacted: bool
    remaining_gaps: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "gateway": self.gateway,
            "gateway_id_hash": self.gateway_id_hash,
            "approval_gateway_hash": self.approval_gateway_hash,
            "policy_hash": self.policy_hash,
            "tenant_hash": self.tenant_hash,
            "evidence_hash": self.evidence_hash,
            "simulator_decision_hash": self.simulator_decision_hash,
            "approval_hash": self.approval_hash,
            "approval_reference_hash": self.approval_reference_hash,
            "approver_role_hash": self.approver_role_hash,
            "scope_hash": self.scope_hash,
            "approval_state": self.approval_state,
            "denial_code": self.denial_code,
            "denial_reasons": self.denial_reasons,
            "schema_version": self.schema_version,
            "output_version": self.output_version,
            "hash_algorithm": self.hash_algorithm,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "runtime_execution": self.runtime_execution,
            "deployment_execution": self.deployment_execution,
            "policy_mutation": self.policy_mutation,
            "network_access": self.network_access,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
            "remaining_gaps": self.remaining_gaps,
        }


def validate_human_approval(
    request: HumanApprovalGatewayRequest | Mapping[str, Any],
) -> HumanApprovalGatewayDecision:
    """Validate external approval metadata without authorizing execution."""

    payload, request_reasons = _request_payload(request)
    simulator_metadata, simulator_reasons = _metadata_payload(payload.get("simulator_metadata"), REQUIRED_SIMULATOR_FIELDS)
    approval_metadata, approval_reasons = _metadata_payload(payload.get("approval_metadata"), REQUIRED_APPROVAL_FIELDS)
    reasons = list(request_reasons)
    reasons.extend(simulator_reasons)
    reasons.extend(approval_reasons)
    reasons.extend(_request_denials(payload))
    reasons.extend(_simulator_denials(payload, simulator_metadata))
    reasons.extend(_approval_denials(payload, approval_metadata))
    denial_reasons = tuple(sorted(set(reasons)))
    if RAW_APPROVAL_CONTENT in denial_reasons or MALFORMED_METADATA in denial_reasons and not payload:
        return _decision(payload, approval_metadata, APPROVAL_FAILED_CLOSED, denial_reasons)
    if APPROVAL_EXPIRED_REASON in denial_reasons:
        return _decision(payload, approval_metadata, APPROVAL_EXPIRED, denial_reasons)
    if denial_reasons and set(denial_reasons).issubset({MISSING_APPROVAL_REFERENCE, MISSING_APPROVAL_HASH, APPROVAL_NOT_GRANTED}):
        return _decision(payload, approval_metadata, APPROVAL_REQUIRED, denial_reasons)
    if denial_reasons:
        return _decision(payload, approval_metadata, APPROVAL_BLOCKED, denial_reasons)
    return _decision(payload, approval_metadata, APPROVAL_VALID, ())


def _request_payload(request: HumanApprovalGatewayRequest | Mapping[str, Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
    if isinstance(request, HumanApprovalGatewayRequest):
        payload = request.as_dict()
    elif isinstance(request, Mapping):
        payload = dict(request)
    else:
        return {}, (MALFORMED_METADATA,)
    reasons: list[str] = []
    if REQUIRED_REQUEST_FIELDS.difference(payload):
        reasons.append(MALFORMED_METADATA)
    if set(payload).difference(REQUIRED_REQUEST_FIELDS):
        reasons.append(UNKNOWN_METADATA)
    if _contains_raw_approval_content(payload):
        reasons.append(RAW_APPROVAL_CONTENT)
    return payload, tuple(reasons)


def _metadata_payload(value: Any, required_fields: frozenset[str]) -> tuple[dict[str, Any], tuple[str, ...]]:
    if not isinstance(value, Mapping):
        return {}, (MALFORMED_METADATA,)
    payload = dict(value)
    reasons: list[str] = []
    if required_fields.difference(payload):
        reasons.append(MALFORMED_METADATA)
    if set(payload).difference(required_fields):
        reasons.append(UNKNOWN_METADATA)
    if _contains_raw_approval_content(payload):
        reasons.append(RAW_APPROVAL_CONTENT)
    return payload, tuple(reasons)


def _request_denials(payload: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    if not isinstance(payload.get("gateway_id"), str) or not _ID_RE.match(payload.get("gateway_id", "")):
        reasons.append(MALFORMED_METADATA)
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        reasons.append(UNSUPPORTED_SCHEMA)
    if payload.get("output_version") != SUPPORTED_OUTPUT_VERSION:
        reasons.append(UNSUPPORTED_VERSION)
    if payload.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(UNSUPPORTED_HASH_ALGORITHM)
    if not isinstance(payload.get("approval_reference"), str) or not _REFERENCE_RE.match(payload.get("approval_reference", "")):
        reasons.append(MISSING_APPROVAL_REFERENCE)
    for field in ("policy_hash", "tenant_hash", "evidence_hash", "approver_role_hash", "scope_hash"):
        if not _is_hash(payload.get(field)):
            reasons.append(INVALID_HASH)
    for field, reason in (
        ("simulator_decision_hash", MISSING_SIMULATOR_HASH),
        ("approval_hash", MISSING_APPROVAL_HASH),
    ):
        if not payload.get(field):
            reasons.append(reason)
        elif not _is_hash(payload.get(field)):
            reasons.append(INVALID_HASH)
    if not _valid_timestamp(payload.get("as_of")):
        reasons.append(MALFORMED_METADATA)
    prior = payload.get("prior_approval_hashes")
    if not isinstance(prior, (list, tuple)):
        reasons.append(MALFORMED_METADATA)
    elif any(not _is_hash(item) for item in prior):
        reasons.append(INVALID_HASH)
    elif payload.get("approval_hash") in prior:
        reasons.extend((DUPLICATE_APPROVAL_REFERENCE, REPLAYED_APPROVAL_REFERENCE))
    reasons.extend(_flag_denials(payload))
    return tuple(reasons)


def _simulator_denials(request: Mapping[str, Any], simulator: Mapping[str, Any]) -> tuple[str, ...]:
    if not simulator:
        return (MISSING_SIMULATOR_REFERENCE,)
    reasons: list[str] = []
    if simulator.get("component") != SUPPORTED_SIMULATOR_COMPONENT:
        reasons.append(UNKNOWN_COMPONENT)
    if simulator.get("schema_version") != SUPPORTED_SIMULATOR_SCHEMA:
        reasons.append(UNSUPPORTED_SCHEMA)
    if simulator.get("output_version") != SUPPORTED_SIMULATOR_OUTPUT:
        reasons.append(UNSUPPORTED_VERSION)
    if simulator.get("simulation_state") != SUPPORTED_SIMULATOR_STATE:
        reasons.append(MISSING_SIMULATOR_REFERENCE)
    if simulator.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(UNSUPPORTED_HASH_ALGORITHM)
    if not _is_hash(simulator.get("simulation_hash")):
        reasons.append(MISSING_SIMULATOR_HASH)
    if simulator.get("simulation_hash") != request.get("simulator_decision_hash"):
        reasons.append(SIMULATOR_HASH_MISMATCH)
    reasons.extend(_shared_hash_denials(request, simulator))
    reasons.extend(_flag_denials(simulator))
    return tuple(reasons)


def _approval_denials(request: Mapping[str, Any], approval: Mapping[str, Any]) -> tuple[str, ...]:
    if not approval:
        return (MISSING_APPROVAL_REFERENCE,)
    reasons: list[str] = []
    if approval.get("component") != SUPPORTED_APPROVAL_COMPONENT:
        reasons.append(UNKNOWN_COMPONENT)
    if approval.get("schema_version") != SUPPORTED_APPROVAL_SCHEMA:
        reasons.append(UNSUPPORTED_SCHEMA)
    if approval.get("output_version") != SUPPORTED_APPROVAL_OUTPUT:
        reasons.append(UNSUPPORTED_VERSION)
    if approval.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(UNSUPPORTED_HASH_ALGORITHM)
    if approval.get("approval_status") not in SUPPORTED_APPROVAL_STATUSES:
        reasons.append(MALFORMED_METADATA)
    elif approval.get("approval_status") != "APPROVED":
        reasons.append(APPROVAL_NOT_GRANTED)
    if approval.get("approval_reference") != request.get("approval_reference"):
        reasons.append(MISSING_APPROVAL_REFERENCE)
    if not _is_hash(approval.get("approval_hash")):
        reasons.append(MISSING_APPROVAL_HASH)
    elif approval.get("approval_hash") != request.get("approval_hash"):
        reasons.append(MISSING_APPROVAL_HASH)
    if approval.get("approver_role_hash") != request.get("approver_role_hash"):
        reasons.append(WRONG_APPROVER_ROLE)
    if approval.get("scope_hash") != request.get("scope_hash"):
        reasons.append(WRONG_APPROVAL_SCOPE)
    if approval.get("simulator_decision_hash") != request.get("simulator_decision_hash"):
        reasons.append(SIMULATOR_HASH_MISMATCH)
    reasons.extend(_shared_hash_denials(request, approval))
    reasons.extend(_timestamp_denials(request, approval))
    return tuple(reasons)


def _shared_hash_denials(request: Mapping[str, Any], metadata: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    for field in ("policy_hash", "tenant_hash", "evidence_hash"):
        if not _is_hash(metadata.get(field)):
            reasons.append(INVALID_HASH)
    if metadata.get("policy_hash") != request.get("policy_hash"):
        reasons.append(POLICY_MISMATCH)
    if metadata.get("tenant_hash") != request.get("tenant_hash"):
        reasons.append(TENANT_MISMATCH)
    if metadata.get("evidence_hash") != request.get("evidence_hash"):
        reasons.append(EVIDENCE_MISMATCH)
    return tuple(reasons)


def _timestamp_denials(request: Mapping[str, Any], approval: Mapping[str, Any]) -> tuple[str, ...]:
    issued_at = _parse_timestamp(approval.get("issued_at"))
    expires_at = _parse_timestamp(approval.get("expires_at"))
    as_of = _parse_timestamp(request.get("as_of"))
    if issued_at is None or expires_at is None or as_of is None:
        return (MALFORMED_METADATA,)
    if expires_at <= as_of:
        return (APPROVAL_EXPIRED_REASON,)
    if issued_at > as_of and (issued_at - as_of).total_seconds() > FUTURE_TIMESTAMP_TOLERANCE_SECONDS:
        return (APPROVAL_TIMESTAMP_IN_FUTURE,)
    return ()


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
    if payload.get("runtime_execution") is True:
        reasons.append(RUNTIME_EXECUTION_ENABLED)
    if payload.get("deployment_execution") is True:
        reasons.append(DEPLOYMENT_EXECUTION_ENABLED)
    if payload.get("policy_mutation") is True:
        reasons.append(POLICY_MUTATION_ENABLED)
    if payload.get("network_access") is True:
        reasons.append(NETWORK_ACCESS_ENABLED)
    return tuple(reasons)


def _decision(
    request: Mapping[str, Any],
    approval: Mapping[str, Any],
    state: str,
    denial_reasons: tuple[str, ...],
) -> HumanApprovalGatewayDecision:
    payload = {
        "gateway": GATEWAY_NAME,
        "gateway_id_hash": _hash_text(str(request.get("gateway_id", ""))),
        "policy_hash": request.get("policy_hash"),
        "tenant_hash": request.get("tenant_hash"),
        "evidence_hash": request.get("evidence_hash"),
        "simulator_decision_hash": request.get("simulator_decision_hash"),
        "approval_hash": request.get("approval_hash"),
        "approval_reference_hash": _hash_text(str(request.get("approval_reference", ""))),
        "approver_role_hash": request.get("approver_role_hash"),
        "scope_hash": request.get("scope_hash"),
        "approval_status": approval.get("approval_status"),
        "approval_state": state,
        "denial_reasons": denial_reasons,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "runtime_execution": False,
        "deployment_execution": False,
        "policy_mutation": False,
        "network_access": False,
        "hash_only": True,
        "redacted": True,
    }
    return HumanApprovalGatewayDecision(
        gateway=GATEWAY_NAME,
        gateway_id_hash=_hash_text(str(request.get("gateway_id"))) if isinstance(request.get("gateway_id"), str) else None,
        approval_gateway_hash=_canonical_hash(payload),
        policy_hash=_valid_hash_or_none(request.get("policy_hash")),
        tenant_hash=_valid_hash_or_none(request.get("tenant_hash")),
        evidence_hash=_valid_hash_or_none(request.get("evidence_hash")),
        simulator_decision_hash=_valid_hash_or_none(request.get("simulator_decision_hash")),
        approval_hash=_valid_hash_or_none(request.get("approval_hash")),
        approval_reference_hash=_hash_text(request.get("approval_reference")) if isinstance(request.get("approval_reference"), str) else None,
        approver_role_hash=_valid_hash_or_none(request.get("approver_role_hash")),
        scope_hash=_valid_hash_or_none(request.get("scope_hash")),
        approval_state=state,
        denial_code=denial_reasons[0] if denial_reasons else None,
        denial_reasons=denial_reasons,
        schema_version=SUPPORTED_SCHEMA_VERSION,
        output_version=SUPPORTED_OUTPUT_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        runtime_execution=False,
        deployment_execution=False,
        policy_mutation=False,
        network_access=False,
        hash_only=True,
        redacted=True,
        remaining_gaps=_remaining_gaps(state),
    )


def _remaining_gaps(state: str) -> tuple[str, ...]:
    if state == APPROVAL_VALID:
        return ("approval_metadata_does_not_authorize_execution", "controlled_sandbox_gateway_required_before_execution")
    if state == APPROVAL_REQUIRED:
        return ("external_human_approval_reference_required",)
    if state == APPROVAL_EXPIRED:
        return ("fresh_external_human_approval_reference_required",)
    return ("approval_gateway_blocked_until_metadata_is_valid",)


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not _TIMESTAMP_RE.match(value):
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _valid_timestamp(value: Any) -> bool:
    return _parse_timestamp(value) is not None


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH_RE.match(value) is not None


def _valid_hash_or_none(value: Any) -> str | None:
    return value if _is_hash(value) else None


def _contains_raw_approval_content(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).lower() in _RAW_APPROVAL_KEYS or _contains_raw_approval_content(child) for key, child in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_raw_approval_content(item) for item in value)
    return False


def _hash_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()
