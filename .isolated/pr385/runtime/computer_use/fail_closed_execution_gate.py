from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from governance.hashing import sha256_reference


ALLOW = "ALLOW"

GATE_ALLOWED = "ALLOWED"
GATE_BLOCKED = "BLOCKED"
GATE_HOLD = "HOLD"
GATE_ERROR = "ERROR"
GATE_UNKNOWN = "UNKNOWN"

APPROVAL_VALID = "VALID"
APPROVAL_PENDING = "PENDING"
APPROVAL_MISSING = "MISSING"
APPROVAL_INVALID = "INVALID"
APPROVAL_EXPIRED = "EXPIRED"

RUNTIME_READY = "READY"
RUNTIME_DEGRADED = "DEGRADED"
RUNTIME_BLOCKED = "BLOCKED"
RUNTIME_UNKNOWN = "UNKNOWN"

REQUIRED_REQUEST_FIELDS = ("request_id", "tenant_id", "actor", "action", "target", "policy_version")
SENSITIVE_REQUEST_FIELDS = frozenset({"raw_payload", "secret", "token", "private_key", "credential", "password"})
SUPPORTED_FINAL_DECISIONS = frozenset({ALLOW, "DENY", "BLOCK", "HOLD", "REVIEW_REQUIRED"})
SUPPORTED_GATE_STATUSES = frozenset({GATE_ALLOWED, GATE_BLOCKED, GATE_HOLD, GATE_ERROR, GATE_UNKNOWN})
SUPPORTED_RUNTIME_STATES = frozenset({RUNTIME_READY, RUNTIME_DEGRADED, RUNTIME_BLOCKED, RUNTIME_UNKNOWN})
REQUIRED_REASON_CODES = (
    "POLICY_DENIED",
    "POLICY_UNKNOWN",
    "APPROVAL_MISSING",
    "APPROVAL_EXPIRED",
    "APPROVAL_INVALID",
    "CONTRACT_INVALID",
    "CAPABILITY_DENIED",
    "TARGET_NOT_ALLOWED",
    "PARAMETERS_INVALID",
    "REPLAY_DETECTED",
    "NONCE_INVALID",
    "TIMESTAMP_INVALID",
    "AUDIT_WRITE_FAILED",
    "AUDIT_VERIFICATION_FAILED",
    "RUNTIME_NOT_READY",
    "DEPENDENCY_NOT_READY",
    "PROVIDER_EXECUTION_DISABLED",
    "PRODUCTION_ACTIVATION_DISABLED",
    "DEPLOYMENT_NOT_AUTHORIZED",
    "MALFORMED_INPUT",
    "UNSUPPORTED_STATE",
    "INTERNAL_ERROR",
)
FALSE_FLAGS = {
    "execution_allowed": False,
    "provider_execution": False,
    "production_activation": False,
    "deployment_authorized": False,
    "release_authorized": False,
}


@dataclass(frozen=True)
class RuntimeExecutionGateDecision:
    gate_status: str
    reason_code: str
    request_hash: str
    audit_hash: str
    policy_hash: str
    approval_state: str
    final_decision: str
    runtime_state: str
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False
    release_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "gate_status": self.gate_status,
            "reason_code": self.reason_code,
            "request_hash": self.request_hash,
            "audit_hash": self.audit_hash,
            "policy_hash": self.policy_hash,
            "approval_state": self.approval_state,
            "final_decision": self.final_decision,
            "runtime_state": self.runtime_state,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "deployment_authorized": self.deployment_authorized,
            "release_authorized": self.release_authorized,
        }
        return {**payload, "decision_hash": sha256_reference(payload)}


def evaluate_runtime_execution_gate(
    request: Mapping[str, Any] | None,
    *,
    policy_evaluation: Mapping[str, Any] | None,
    final_decision: str | None,
    approval_state: Mapping[str, Any] | None,
    execution_contract: Mapping[str, Any] | None,
    capability: Mapping[str, Any] | None,
    target_policy: Mapping[str, Any] | None,
    parameter_validation: Mapping[str, Any] | None,
    replay_protection: Mapping[str, Any] | None,
    nonce_state: Mapping[str, Any] | None,
    timestamp_state: Mapping[str, Any] | None,
    audit_gate: Mapping[str, Any] | None,
    runtime_state: str | None,
    dependencies: Sequence[Mapping[str, Any]] | None,
    provider_execution_permitted: bool,
    production_activation_permitted: bool,
    deployment_authorized: bool,
) -> RuntimeExecutionGateDecision:
    try:
        return _evaluate_runtime_execution_gate(
            request,
            policy_evaluation=policy_evaluation,
            final_decision=final_decision,
            approval_state=approval_state,
            execution_contract=execution_contract,
            capability=capability,
            target_policy=target_policy,
            parameter_validation=parameter_validation,
            replay_protection=replay_protection,
            nonce_state=nonce_state,
            timestamp_state=timestamp_state,
            audit_gate=audit_gate,
            runtime_state=runtime_state,
            dependencies=dependencies,
            provider_execution_permitted=provider_execution_permitted,
            production_activation_permitted=production_activation_permitted,
            deployment_authorized=deployment_authorized,
        )
    except Exception:
        return _decision(GATE_ERROR, "INTERNAL_ERROR", sha256_reference({}), "", "", "", "", "")


def _evaluate_runtime_execution_gate(
    request: Mapping[str, Any] | None,
    *,
    policy_evaluation: Mapping[str, Any] | None,
    final_decision: str | None,
    approval_state: Mapping[str, Any] | None,
    execution_contract: Mapping[str, Any] | None,
    capability: Mapping[str, Any] | None,
    target_policy: Mapping[str, Any] | None,
    parameter_validation: Mapping[str, Any] | None,
    replay_protection: Mapping[str, Any] | None,
    nonce_state: Mapping[str, Any] | None,
    timestamp_state: Mapping[str, Any] | None,
    audit_gate: Mapping[str, Any] | None,
    runtime_state: str | None,
    dependencies: Sequence[Mapping[str, Any]] | None,
    provider_execution_permitted: bool,
    production_activation_permitted: bool,
    deployment_authorized: bool,
) -> RuntimeExecutionGateDecision:
    request_hash = sha256_reference(_redacted_request(request)) if isinstance(request, Mapping) else sha256_reference({})
    policy_hash = _extract_hash(policy_evaluation, "policy_hash")
    audit_hash = _extract_hash(audit_gate, "audit_hash")
    approval_status = str(approval_state.get("status", "")) if isinstance(approval_state, Mapping) else ""
    final = str(final_decision or "")
    runtime = str(runtime_state or "")

    request_error = _validate_request(request)
    if request_error:
        return _decision(GATE_BLOCKED, request_error, request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if not isinstance(policy_evaluation, Mapping):
        return _decision(GATE_BLOCKED, "POLICY_UNKNOWN", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if policy_evaluation.get("succeeded") is not True or not _is_hash(policy_hash):
        return _decision(GATE_BLOCKED, "POLICY_UNKNOWN", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if final_decision is None or final == "":
        return _decision(GATE_BLOCKED, "POLICY_UNKNOWN", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if final not in SUPPORTED_FINAL_DECISIONS:
        return _decision(GATE_BLOCKED, "UNSUPPORTED_STATE", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if final != ALLOW:
        return _decision(GATE_BLOCKED, "POLICY_DENIED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    approval_error, approval_gate = _validate_approval(approval_state, request)
    if approval_error:
        return _decision(approval_gate, approval_error, request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if not _mapping_bool(execution_contract, "valid"):
        return _decision(GATE_BLOCKED, "CONTRACT_INVALID", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if not _mapping_bool(capability, "authorized"):
        return _decision(GATE_BLOCKED, "CAPABILITY_DENIED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if not _mapping_bool(target_policy, "allowed"):
        return _decision(GATE_BLOCKED, "TARGET_NOT_ALLOWED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if not _mapping_bool(parameter_validation, "valid"):
        return _decision(GATE_BLOCKED, "PARAMETERS_INVALID", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if _mapping_bool(replay_protection, "replayed"):
        return _decision(GATE_BLOCKED, "REPLAY_DETECTED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if not _mapping_bool(replay_protection, "passed"):
        return _decision(GATE_BLOCKED, "REPLAY_DETECTED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if not _mapping_bool(nonce_state, "valid") or nonce_state.get("used") is True:
        return _decision(GATE_BLOCKED, "NONCE_INVALID", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if not _timestamp_valid(timestamp_state):
        return _decision(GATE_BLOCKED, "TIMESTAMP_INVALID", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if runtime_state not in SUPPORTED_RUNTIME_STATES:
        return _decision(GATE_UNKNOWN, "UNSUPPORTED_STATE", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if runtime_state != RUNTIME_READY:
        return _decision(GATE_BLOCKED, "RUNTIME_NOT_READY", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if not _dependencies_ready(dependencies):
        return _decision(GATE_BLOCKED, "DEPENDENCY_NOT_READY", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if provider_execution_permitted is not True:
        return _decision(GATE_BLOCKED, "PROVIDER_EXECUTION_DISABLED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if production_activation_permitted is not True:
        return _decision(GATE_BLOCKED, "PRODUCTION_ACTIVATION_DISABLED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if deployment_authorized is not True:
        return _decision(GATE_BLOCKED, "DEPLOYMENT_NOT_AUTHORIZED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if not isinstance(audit_gate, Mapping) or audit_gate.get("write_succeeded") is not True:
        return _decision(GATE_BLOCKED, "AUDIT_WRITE_FAILED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if audit_gate.get("verified") is not True or not _is_hash(audit_hash):
        return _decision(GATE_BLOCKED, "AUDIT_VERIFICATION_FAILED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)
    if audit_gate.get("before_execute") is not True:
        return _decision(GATE_BLOCKED, "AUDIT_WRITE_FAILED", request_hash, audit_hash, policy_hash, approval_status, final, runtime)

    return RuntimeExecutionGateDecision(
        gate_status=GATE_ALLOWED,
        reason_code="EXECUTION_GATE_ALLOWED",
        request_hash=request_hash,
        audit_hash=audit_hash,
        policy_hash=policy_hash,
        approval_state=approval_status,
        final_decision=final,
        runtime_state=runtime,
        execution_allowed=True,
        provider_execution=True,
        production_activation=True,
        deployment_authorized=True,
    )


def _decision(
    gate_status: str,
    reason_code: str,
    request_hash: str,
    audit_hash: str,
    policy_hash: str,
    approval_state: str,
    final_decision: str,
    runtime_state: str,
) -> RuntimeExecutionGateDecision:
    return RuntimeExecutionGateDecision(
        gate_status=gate_status,
        reason_code=reason_code,
        request_hash=request_hash,
        audit_hash=audit_hash,
        policy_hash=policy_hash,
        approval_state=approval_state,
        final_decision=final_decision,
        runtime_state=runtime_state,
    )


def _validate_request(request: Mapping[str, Any] | None) -> str:
    if not isinstance(request, Mapping):
        return "MALFORMED_INPUT"
    for field in REQUIRED_REQUEST_FIELDS:
        value = request.get(field)
        if not isinstance(value, str) or not value.strip():
            return "MALFORMED_INPUT"
    if any(key in request for key in SENSITIVE_REQUEST_FIELDS):
        return "MALFORMED_INPUT"
    return ""


def _validate_approval(approval_state: Mapping[str, Any] | None, request: Mapping[str, Any] | None) -> tuple[str, str]:
    if not isinstance(approval_state, Mapping):
        return "APPROVAL_MISSING", GATE_BLOCKED
    status = approval_state.get("status")
    if status == APPROVAL_PENDING:
        return "APPROVAL_MISSING", GATE_HOLD
    if status in {"", APPROVAL_MISSING, None}:
        return "APPROVAL_MISSING", GATE_BLOCKED
    if status == APPROVAL_EXPIRED or approval_state.get("expired") is True:
        return "APPROVAL_EXPIRED", GATE_BLOCKED
    if status != APPROVAL_VALID or approval_state.get("valid") is not True:
        return "APPROVAL_INVALID", GATE_BLOCKED
    if approval_state.get("approval_hash") and not _is_hash(approval_state.get("approval_hash")):
        return "APPROVAL_INVALID", GATE_BLOCKED
    if approval_state.get("approver") == (request or {}).get("actor"):
        return "APPROVAL_INVALID", GATE_BLOCKED
    return "", GATE_ALLOWED


def _timestamp_valid(timestamp_state: Mapping[str, Any] | None) -> bool:
    if not isinstance(timestamp_state, Mapping) or timestamp_state.get("valid") is not True:
        return False
    observed = _parse_time(timestamp_state.get("observed_at"))
    not_before = _parse_time(timestamp_state.get("not_before"))
    expires_at = _parse_time(timestamp_state.get("expires_at"))
    if observed is None or not_before is None or expires_at is None:
        return False
    return not_before <= observed < expires_at


def _dependencies_ready(dependencies: Sequence[Mapping[str, Any]] | None) -> bool:
    if not isinstance(dependencies, Sequence) or isinstance(dependencies, (str, bytes)) or not dependencies:
        return False
    return all(isinstance(item, Mapping) and item.get("state") == RUNTIME_READY for item in dependencies)


def _redacted_request(request: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        return {}
    return {field: request.get(field, "") for field in REQUIRED_REQUEST_FIELDS}


def _extract_hash(payload: Mapping[str, Any] | None, field: str) -> str:
    if not isinstance(payload, Mapping):
        return ""
    value = payload.get(field)
    return value if isinstance(value, str) else ""


def _mapping_bool(payload: Mapping[str, Any] | None, field: str) -> bool:
    return isinstance(payload, Mapping) and payload.get(field) is True


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71 and all(char in "0123456789abcdef" for char in value[7:])


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
