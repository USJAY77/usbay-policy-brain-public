"""Deterministic Runtime Approval Gate metadata.

The gate validates hash-only references to external human approvals. It never
creates approval, stores approval content, executes work, calls providers, or
activates production behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Mapping, Sequence


GATE_NAME = "runtime_approval_gate"
APPROVAL_ELIGIBLE = "APPROVAL_ELIGIBLE"
APPROVAL_BLOCKED = "APPROVAL_BLOCKED"
SUPPORTED_SCHEMA_VERSION = "phase-b.runtime-approval-gate.v1"
SUPPORTED_APPROVAL_VERSION = "phase-b.approval-reference.v1"
SUPPORTED_HASH_ALGORITHM = "sha256"
APPROVAL_STATUSES = frozenset({"PENDING", "APPROVED", "REJECTED", "EXPIRED", "REVOKED", "BLOCKED"})

MISSING_APPROVAL = "MISSING_APPROVAL"
PENDING_APPROVAL = "PENDING_APPROVAL"
REJECTED_APPROVAL = "REJECTED_APPROVAL"
REVOKED_APPROVAL = "REVOKED_APPROVAL"
BLOCKED_APPROVAL = "BLOCKED_APPROVAL"
EXPIRED_APPROVAL = "EXPIRED_APPROVAL"
UNKNOWN_APPROVAL_STATUS = "UNKNOWN_APPROVAL_STATUS"
MALFORMED_APPROVAL_ID = "MALFORMED_APPROVAL_ID"
APPROVAL_HASH_MISMATCH = "APPROVAL_HASH_MISMATCH"
INVALID_HASH = "INVALID_HASH"
MISSING_HASH = "MISSING_HASH"
POLICY_HASH_MISMATCH = "POLICY_HASH_MISMATCH"
EVIDENCE_HASH_MISMATCH = "EVIDENCE_HASH_MISMATCH"
TENANT_HASH_MISMATCH = "TENANT_HASH_MISMATCH"
DECISION_CONTINUITY_MISMATCH = "DECISION_CONTINUITY_MISMATCH"
ACTION_CONTRACT_HASH_MISMATCH = "ACTION_CONTRACT_HASH_MISMATCH"
ACTOR_ROLE_HASH_MISMATCH = "ACTOR_ROLE_HASH_MISMATCH"
TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
TIMESTAMP_ORDER_INVALID = "TIMESTAMP_ORDER_INVALID"
FUTURE_APPROVAL_INVALID = "FUTURE_APPROVAL_INVALID"
UNKNOWN_SCHEMA_VERSION = "UNKNOWN_SCHEMA_VERSION"
UNKNOWN_APPROVAL_VERSION = "UNKNOWN_APPROVAL_VERSION"
INVALID_APPROVAL_COUNT = "INVALID_APPROVAL_COUNT"
INSUFFICIENT_APPROVER_COUNT = "INSUFFICIENT_APPROVER_COUNT"
DUAL_APPROVAL_NOT_SATISFIED = "DUAL_APPROVAL_NOT_SATISFIED"
DUPLICATE_APPROVER_REFERENCE = "DUPLICATE_APPROVER_REFERENCE"
MISSING_APPROVER_REFERENCE = "MISSING_APPROVER_REFERENCE"
UNKNOWN_METADATA = "UNKNOWN_METADATA"
RAW_APPROVAL_CONTENT_PRESENT = "RAW_APPROVAL_CONTENT_PRESENT"
SENSITIVE_DATA_PRESENT = "SENSITIVE_DATA_PRESENT"
NON_HASH_ONLY_EVIDENCE = "NON_HASH_ONLY_EVIDENCE"
UNREDACTED_EVIDENCE = "UNREDACTED_EVIDENCE"
EXECUTION_FLAG_ENABLED = "EXECUTION_FLAG_ENABLED"
PROVIDER_EXECUTION_ENABLED = "PROVIDER_EXECUTION_ENABLED"
PRODUCTION_ACTIVATION_ENABLED = "PRODUCTION_ACTIVATION_ENABLED"
INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"

DENIAL_CODES = (
    MISSING_APPROVAL,
    PENDING_APPROVAL,
    REJECTED_APPROVAL,
    REVOKED_APPROVAL,
    BLOCKED_APPROVAL,
    EXPIRED_APPROVAL,
    UNKNOWN_APPROVAL_STATUS,
    MALFORMED_APPROVAL_ID,
    APPROVAL_HASH_MISMATCH,
    INVALID_HASH,
    MISSING_HASH,
    POLICY_HASH_MISMATCH,
    EVIDENCE_HASH_MISMATCH,
    TENANT_HASH_MISMATCH,
    DECISION_CONTINUITY_MISMATCH,
    ACTION_CONTRACT_HASH_MISMATCH,
    ACTOR_ROLE_HASH_MISMATCH,
    TIMESTAMP_INVALID,
    TIMESTAMP_ORDER_INVALID,
    FUTURE_APPROVAL_INVALID,
    UNKNOWN_SCHEMA_VERSION,
    UNKNOWN_APPROVAL_VERSION,
    INVALID_APPROVAL_COUNT,
    INSUFFICIENT_APPROVER_COUNT,
    DUAL_APPROVAL_NOT_SATISFIED,
    DUPLICATE_APPROVER_REFERENCE,
    MISSING_APPROVER_REFERENCE,
    UNKNOWN_METADATA,
    RAW_APPROVAL_CONTENT_PRESENT,
    SENSITIVE_DATA_PRESENT,
    NON_HASH_ONLY_EVIDENCE,
    UNREDACTED_EVIDENCE,
    EXECUTION_FLAG_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    PRODUCTION_ACTIVATION_ENABLED,
    INVALID_FIELD_TYPE,
)

REQUIRED_FIELDS = frozenset({
    "approval_id",
    "approval_hash",
    "policy_hash",
    "evidence_hash",
    "tenant_hash",
    "decision_hash",
    "actor_role_hash",
    "action_contract_hash",
    "issued_at",
    "expires_at",
    "schema_version",
    "approval_version",
    "approval_status",
    "required_approver_count",
    "recorded_approver_count",
    "dual_approval_required",
    "approver_hashes",
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "hash_algorithm",
    "redacted",
    "hash_only",
})
ALLOWED_FIELDS = REQUIRED_FIELDS

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_APPROVAL_ID_RE = re.compile(r"^approval-[a-z0-9][a-z0-9-]{2,63}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SENSITIVE_KEYS = frozenset({
    "api_key",
    "comment",
    "comments",
    "content",
    "credential",
    "credentials",
    "email",
    "name",
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
class RuntimeApprovalGateRequest:
    approval: Mapping[str, Any] | None
    policy_hash: str
    evidence_hash: str
    tenant_hash: str
    decision_hash: str
    actor_role_hash: str
    action_contract_hash: str
    as_of: str


@dataclass(frozen=True)
class RuntimeApprovalGateDecision:
    gate: str
    gate_hash: str
    approval_id_hash: str | None
    approval_hash: str | None
    policy_hash: str | None
    evidence_hash: str | None
    tenant_hash: str | None
    decision_hash: str | None
    actor_role_hash: str | None
    action_contract_hash: str | None
    approval_status: str
    schema_version: str
    approval_version: str
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
            "gate": self.gate,
            "gate_hash": self.gate_hash,
            "approval_id_hash": self.approval_id_hash,
            "approval_hash": self.approval_hash,
            "policy_hash": self.policy_hash,
            "evidence_hash": self.evidence_hash,
            "tenant_hash": self.tenant_hash,
            "decision_hash": self.decision_hash,
            "actor_role_hash": self.actor_role_hash,
            "action_contract_hash": self.action_contract_hash,
            "approval_status": self.approval_status,
            "schema_version": self.schema_version,
            "approval_version": self.approval_version,
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


def validate_runtime_approval(request: RuntimeApprovalGateRequest) -> RuntimeApprovalGateDecision:
    """Validate an external approval reference without authorizing execution."""

    if request.approval is None:
        return _blocked_decision(request, {}, (MISSING_APPROVAL,))
    approval = dict(request.approval)
    reasons = list(_metadata_denials(approval))
    reasons.extend(_request_denials(request))
    reasons.extend(_reference_denials(request, approval))
    reasons.extend(_approval_status_denials(approval))
    reasons.extend(_approver_denials(approval))
    reasons.extend(_timestamp_denials(request, approval))
    denial_reasons = tuple(sorted(set(reasons)))
    if denial_reasons:
        return _blocked_decision(request, approval, denial_reasons)
    return _eligible_decision(request, approval)


def deterministic_approval_hash(approval: Mapping[str, Any]) -> str:
    """Return the canonical hash for approval metadata excluding approval_hash."""

    payload = {
        field: approval[field]
        for field in sorted(REQUIRED_FIELDS - {"approval_hash"})
        if field in approval
    }
    return _canonical_hash(payload)


def _metadata_denials(approval: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    missing = REQUIRED_FIELDS.difference(approval)
    if missing:
        reasons.append(MISSING_APPROVAL)
    if set(approval).difference(ALLOWED_FIELDS):
        reasons.append(UNKNOWN_METADATA)
    if _contains_raw_content(approval):
        reasons.append(RAW_APPROVAL_CONTENT_PRESENT)
    if _contains_sensitive_data(approval):
        reasons.append(SENSITIVE_DATA_PRESENT)
    for field in REQUIRED_FIELDS:
        if field not in approval:
            continue
        value = approval[field]
        if field in {"approval_id", "approval_hash", "policy_hash", "evidence_hash", "tenant_hash", "decision_hash", "actor_role_hash", "action_contract_hash", "issued_at", "expires_at", "schema_version", "approval_version", "approval_status", "hash_algorithm"} and not isinstance(value, str):
            reasons.append(INVALID_FIELD_TYPE)
        if field in {"required_approver_count", "recorded_approver_count"} and (not isinstance(value, int) or isinstance(value, bool)):
            reasons.append(INVALID_FIELD_TYPE)
        if field in {"dual_approval_required", "execution_allowed", "provider_execution", "production_activation", "redacted", "hash_only"} and not isinstance(value, bool):
            reasons.append(INVALID_FIELD_TYPE)
    for field in ("approval_hash", "policy_hash", "evidence_hash", "tenant_hash", "decision_hash", "actor_role_hash", "action_contract_hash"):
        value = approval.get(field)
        if not value:
            reasons.append(MISSING_HASH)
        elif isinstance(value, str) and not _HASH_RE.match(value):
            reasons.append(INVALID_HASH)
    if isinstance(approval.get("approval_id"), str) and not _APPROVAL_ID_RE.match(approval["approval_id"]):
        reasons.append(MALFORMED_APPROVAL_ID)
    if approval.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        reasons.append(UNKNOWN_SCHEMA_VERSION)
    if approval.get("approval_version") != SUPPORTED_APPROVAL_VERSION:
        reasons.append(UNKNOWN_APPROVAL_VERSION)
    if approval.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        reasons.append(INVALID_HASH)
    if approval.get("hash_only") is not True:
        reasons.append(NON_HASH_ONLY_EVIDENCE)
    if approval.get("redacted") is not True:
        reasons.append(UNREDACTED_EVIDENCE)
    if approval.get("execution_allowed") is not False:
        reasons.append(EXECUTION_FLAG_ENABLED)
    if approval.get("provider_execution") is not False:
        reasons.append(PROVIDER_EXECUTION_ENABLED)
    if approval.get("production_activation") is not False:
        reasons.append(PRODUCTION_ACTIVATION_ENABLED)
    if REQUIRED_FIELDS.issubset(approval) and approval.get("approval_hash") != deterministic_approval_hash(approval):
        reasons.append(APPROVAL_HASH_MISMATCH)
    return tuple(reasons)


def _request_denials(request: RuntimeApprovalGateRequest) -> tuple[str, ...]:
    reasons: list[str] = []
    for value in (
        request.policy_hash,
        request.evidence_hash,
        request.tenant_hash,
        request.decision_hash,
        request.actor_role_hash,
        request.action_contract_hash,
    ):
        if not value:
            reasons.append(MISSING_HASH)
        elif not _HASH_RE.match(value):
            reasons.append(INVALID_HASH)
    if not isinstance(request.as_of, str) or not _TIMESTAMP_RE.match(request.as_of):
        reasons.append(TIMESTAMP_INVALID)
    return tuple(reasons)


def _reference_denials(request: RuntimeApprovalGateRequest, approval: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    if approval.get("policy_hash") != request.policy_hash:
        reasons.append(POLICY_HASH_MISMATCH)
    if approval.get("evidence_hash") != request.evidence_hash:
        reasons.append(EVIDENCE_HASH_MISMATCH)
    if approval.get("tenant_hash") != request.tenant_hash:
        reasons.append(TENANT_HASH_MISMATCH)
    if approval.get("decision_hash") != request.decision_hash:
        reasons.append(DECISION_CONTINUITY_MISMATCH)
    if approval.get("action_contract_hash") != request.action_contract_hash:
        reasons.append(ACTION_CONTRACT_HASH_MISMATCH)
    if approval.get("actor_role_hash") != request.actor_role_hash:
        reasons.append(ACTOR_ROLE_HASH_MISMATCH)
    return tuple(reasons)


def _approval_status_denials(approval: Mapping[str, Any]) -> tuple[str, ...]:
    status = approval.get("approval_status")
    if status not in APPROVAL_STATUSES:
        return (UNKNOWN_APPROVAL_STATUS,)
    if status == "PENDING":
        return (PENDING_APPROVAL,)
    if status == "REJECTED":
        return (REJECTED_APPROVAL,)
    if status == "REVOKED":
        return (REVOKED_APPROVAL,)
    if status == "BLOCKED":
        return (BLOCKED_APPROVAL,)
    if status == "EXPIRED":
        return (EXPIRED_APPROVAL,)
    return ()


def _approver_denials(approval: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    required_count = approval.get("required_approver_count")
    recorded_count = approval.get("recorded_approver_count")
    approver_hashes = approval.get("approver_hashes")
    if not isinstance(required_count, int) or isinstance(required_count, bool) or required_count < 1:
        reasons.append(INVALID_APPROVAL_COUNT)
    if not isinstance(recorded_count, int) or isinstance(recorded_count, bool) or recorded_count < 0:
        reasons.append(INVALID_APPROVAL_COUNT)
    if not isinstance(approver_hashes, Sequence) or isinstance(approver_hashes, (str, bytes)):
        reasons.append(MISSING_APPROVER_REFERENCE)
        approver_hashes = ()
    if any(not isinstance(item, str) or not _HASH_RE.match(item) for item in approver_hashes):
        reasons.append(INVALID_HASH)
    if len(tuple(approver_hashes)) != len(set(approver_hashes)):
        reasons.append(DUPLICATE_APPROVER_REFERENCE)
    if isinstance(required_count, int) and isinstance(recorded_count, int) and recorded_count < required_count:
        reasons.append(INSUFFICIENT_APPROVER_COUNT)
    if isinstance(recorded_count, int) and len(tuple(approver_hashes)) < recorded_count:
        reasons.append(MISSING_APPROVER_REFERENCE)
    if approval.get("dual_approval_required") is True and (recorded_count < 2 or len(set(approver_hashes)) < 2):
        reasons.append(DUAL_APPROVAL_NOT_SATISFIED)
    return tuple(reasons)


def _timestamp_denials(request: RuntimeApprovalGateRequest, approval: Mapping[str, Any]) -> tuple[str, ...]:
    issued_at = approval.get("issued_at")
    expires_at = approval.get("expires_at")
    if not isinstance(issued_at, str) or not _TIMESTAMP_RE.match(issued_at):
        return (TIMESTAMP_INVALID,)
    if not isinstance(expires_at, str) or not _TIMESTAMP_RE.match(expires_at):
        return (TIMESTAMP_INVALID,)
    if expires_at <= issued_at:
        return (TIMESTAMP_ORDER_INVALID,)
    if _TIMESTAMP_RE.match(request.as_of):
        if issued_at > request.as_of:
            return (FUTURE_APPROVAL_INVALID,)
        if expires_at <= request.as_of:
            return (EXPIRED_APPROVAL,)
    return ()


def _eligible_decision(
    request: RuntimeApprovalGateRequest,
    approval: Mapping[str, Any],
) -> RuntimeApprovalGateDecision:
    payload = _decision_payload(request, approval, APPROVAL_ELIGIBLE, ())
    return RuntimeApprovalGateDecision(
        gate=GATE_NAME,
        gate_hash=_canonical_hash(payload),
        approval_id_hash=_hash_text(approval["approval_id"]),
        approval_hash=approval["approval_hash"],
        policy_hash=request.policy_hash,
        evidence_hash=request.evidence_hash,
        tenant_hash=request.tenant_hash,
        decision_hash=request.decision_hash,
        actor_role_hash=request.actor_role_hash,
        action_contract_hash=request.action_contract_hash,
        approval_status=approval["approval_status"],
        schema_version=SUPPORTED_SCHEMA_VERSION,
        approval_version=SUPPORTED_APPROVAL_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        hash_only=True,
        redacted=True,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        status=APPROVAL_ELIGIBLE,
        denial_code=None,
        denial_reasons=(),
        remaining_gaps=("human_approval_content_remains_external", "gate_does_not_authorize_execution"),
    )


def _blocked_decision(
    request: RuntimeApprovalGateRequest,
    approval: Mapping[str, Any],
    denial_reasons: tuple[str, ...],
) -> RuntimeApprovalGateDecision:
    payload = _decision_payload(request, approval, APPROVAL_BLOCKED, denial_reasons)
    return RuntimeApprovalGateDecision(
        gate=GATE_NAME,
        gate_hash=_canonical_hash(payload),
        approval_id_hash=_hash_text(str(approval["approval_id"])) if isinstance(approval.get("approval_id"), str) else None,
        approval_hash=approval.get("approval_hash") if isinstance(approval.get("approval_hash"), str) and _HASH_RE.match(approval["approval_hash"]) else None,
        policy_hash=request.policy_hash if _HASH_RE.match(request.policy_hash or "") else None,
        evidence_hash=request.evidence_hash if _HASH_RE.match(request.evidence_hash or "") else None,
        tenant_hash=request.tenant_hash if _HASH_RE.match(request.tenant_hash or "") else None,
        decision_hash=request.decision_hash if _HASH_RE.match(request.decision_hash or "") else None,
        actor_role_hash=request.actor_role_hash if _HASH_RE.match(request.actor_role_hash or "") else None,
        action_contract_hash=request.action_contract_hash if _HASH_RE.match(request.action_contract_hash or "") else None,
        approval_status=approval.get("approval_status") if isinstance(approval.get("approval_status"), str) else "BLOCKED",
        schema_version=SUPPORTED_SCHEMA_VERSION,
        approval_version=SUPPORTED_APPROVAL_VERSION,
        hash_algorithm=SUPPORTED_HASH_ALGORITHM,
        hash_only=True,
        redacted=True,
        execution_allowed=False,
        provider_execution=False,
        production_activation=False,
        status=APPROVAL_BLOCKED,
        denial_code=denial_reasons[0],
        denial_reasons=denial_reasons,
        remaining_gaps=("approval_gate_blocked_until_reference_is_valid",),
    )


def _decision_payload(
    request: RuntimeApprovalGateRequest,
    approval: Mapping[str, Any],
    status: str,
    denial_reasons: tuple[str, ...],
) -> Mapping[str, Any]:
    return {
        "gate": GATE_NAME,
        "approval_id_hash": _hash_text(str(approval.get("approval_id", "missing"))),
        "approval_hash": approval.get("approval_hash"),
        "policy_hash": request.policy_hash,
        "evidence_hash": request.evidence_hash,
        "tenant_hash": request.tenant_hash,
        "decision_hash": request.decision_hash,
        "actor_role_hash": request.actor_role_hash,
        "action_contract_hash": request.action_contract_hash,
        "as_of_hash": _hash_text(request.as_of),
        "status": status,
        "denial_reasons": denial_reasons,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "hash_only": True,
        "redacted": True,
    }


def _contains_raw_content(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).lower() in {"comment", "comments", "content", "raw", "raw_payload", "payload"} or _contains_raw_content(child) for key, child in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_raw_content(item) for item in value)
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
