from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from governance.hashing import sha256_reference


REGISTERED = "REGISTERED"
READY = "READY"
DEGRADED = "DEGRADED"
DISABLED = "DISABLED"
BLOCKED = "BLOCKED"
UNSUPPORTED = "UNSUPPORTED"
TIMEOUT = "TIMEOUT"
FAILED = "FAILED"

ALLOWED = "ALLOWED"
DECISION_BLOCKED = "BLOCKED"
HOLD = "HOLD"

SUPPORTED_ADAPTER_STATES = frozenset({REGISTERED, READY, DEGRADED, DISABLED, BLOCKED, UNSUPPORTED, TIMEOUT, FAILED})
SUPPORTED_ADAPTERS = frozenset({"local_mock_adapter", "timeout_adapter", "blocked_adapter", "malformed_adapter"})
REQUIRED_CONTRACT_FIELDS = (
    "adapter_id",
    "adapter_type",
    "provider_class",
    "capability_id",
    "execution_contract",
    "policy_version",
    "approval_reference",
    "runtime_reference",
    "dependency_reference",
    "audit_reference",
    "timeout_seconds",
    "dry_run",
    "provider_version",
    "expected_version",
    "observed_version",
    "execution_status",
    "decision",
    "target",
    "evidence_reference",
)
REQUIRED_PRECHECKS = (
    "policy_evaluated",
    "approval_valid",
    "execution_contract_valid",
    "capability_authorized",
    "target_policy_valid",
    "dependency_ready",
    "runtime_ready",
    "replay_protection_passed",
    "nonce_valid",
    "timestamp_window_valid",
    "parameters_valid",
    "evidence_destination_ready",
)
SENSITIVE_CONTRACT_FIELDS = frozenset({"prompt", "payload", "token", "credential", "personal_data", "secret", "password", "raw_payload"})


@dataclass(frozen=True)
class AdapterExecutionDecision:
    decision: str
    reason_code: str
    adapter_id: str
    adapter_state: str
    contract_hash: str
    evidence_hash: str
    adapter_result_hash: str
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "decision": self.decision,
            "reason_code": self.reason_code,
            "adapter_id": self.adapter_id,
            "adapter_state": self.adapter_state,
            "contract_hash": self.contract_hash,
            "evidence_hash": self.evidence_hash,
            "adapter_result_hash": self.adapter_result_hash,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "deployment_authorized": self.deployment_authorized,
        }
        return {**payload, "decision_hash": sha256_reference(payload)}


def evaluate_execution_adapter_contract(
    adapter_contract: Mapping[str, Any] | None,
    *,
    prechecks: Mapping[str, Any] | None,
    adapter_registry: Mapping[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]] | None = None,
) -> AdapterExecutionDecision:
    try:
        return _evaluate_execution_adapter_contract(
            adapter_contract,
            prechecks=prechecks,
            adapter_registry=adapter_registry or default_mock_adapters(),
        )
    except Exception:
        return _blocked("INTERNAL_ERROR", _adapter_id(adapter_contract), _adapter_state(adapter_contract), _contract_hash(adapter_contract), "")


def _evaluate_execution_adapter_contract(
    adapter_contract: Mapping[str, Any] | None,
    *,
    prechecks: Mapping[str, Any] | None,
    adapter_registry: Mapping[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]],
) -> AdapterExecutionDecision:
    contract_hash = _contract_hash(adapter_contract)
    adapter_id = _adapter_id(adapter_contract)
    adapter_state = _adapter_state(adapter_contract)
    contract_error = _contract_error(adapter_contract)
    if contract_error:
        return _blocked(contract_error, adapter_id, adapter_state, contract_hash, "")
    precheck_error = _precheck_error(prechecks)
    if precheck_error:
        return _blocked(precheck_error, adapter_id, adapter_state, contract_hash, "")
    adapter_error = _adapter_registration_error(adapter_contract, adapter_registry)
    if adapter_error:
        return _blocked(adapter_error, adapter_id, adapter_state, contract_hash, "")

    adapter = adapter_registry[adapter_id]
    try:
        adapter_result = adapter(adapter_contract)
    except TimeoutError:
        return _blocked("ADAPTER_TIMEOUT", adapter_id, TIMEOUT, contract_hash, "")
    except Exception:
        return _blocked("ADAPTER_EXCEPTION", adapter_id, FAILED, contract_hash, "")
    if not isinstance(adapter_result, Mapping):
        return _blocked("MALFORMED_ADAPTER_RESPONSE", adapter_id, adapter_state, contract_hash, "")
    status = adapter_result.get("execution_status")
    if status == TIMEOUT:
        return _blocked("ADAPTER_TIMEOUT", adapter_id, TIMEOUT, contract_hash, "")
    if status in {BLOCKED, DISABLED}:
        return _blocked("ADAPTER_BLOCKED", adapter_id, str(status), contract_hash, "")
    if status != READY:
        return _blocked("MALFORMED_ADAPTER_RESPONSE", adapter_id, adapter_state, contract_hash, "")
    adapter_result_hash = sha256_reference(_redacted_adapter_result(adapter_result))
    evidence_hash = sha256_reference(
        {
            "adapter_id": adapter_id,
            "adapter_state": READY,
            "adapter_result_hash": adapter_result_hash,
            "contract_hash": contract_hash,
            "dry_run": adapter_contract.get("dry_run"),
        }
    )
    return AdapterExecutionDecision(
        decision=ALLOWED,
        reason_code="GOVERNED_ADAPTER_ALLOWED",
        adapter_id=adapter_id,
        adapter_state=READY,
        contract_hash=contract_hash,
        evidence_hash=evidence_hash,
        adapter_result_hash=adapter_result_hash,
        execution_allowed=True,
    )


def default_mock_adapters() -> dict[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]]:
    return {
        "local_mock_adapter": _local_mock_adapter,
        "timeout_adapter": _timeout_adapter,
        "blocked_adapter": _blocked_adapter,
        "malformed_adapter": _malformed_adapter,
    }


def _local_mock_adapter(adapter_contract: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "execution_status": READY,
        "adapter_id": adapter_contract.get("adapter_id"),
        "result_reference": sha256_reference({"adapter_id": adapter_contract.get("adapter_id"), "dry_run": adapter_contract.get("dry_run")}),
    }


def _timeout_adapter(adapter_contract: Mapping[str, Any]) -> Mapping[str, Any]:
    return {"execution_status": TIMEOUT, "adapter_id": adapter_contract.get("adapter_id")}


def _blocked_adapter(adapter_contract: Mapping[str, Any]) -> Mapping[str, Any]:
    return {"execution_status": BLOCKED, "adapter_id": adapter_contract.get("adapter_id")}


def _malformed_adapter(adapter_contract: Mapping[str, Any]) -> Mapping[str, Any]:
    return {"adapter_id": adapter_contract.get("adapter_id")}


def _contract_error(adapter_contract: Mapping[str, Any] | None) -> str:
    if not isinstance(adapter_contract, Mapping):
        return "MALFORMED_ADAPTER_CONTRACT"
    if any(field not in adapter_contract for field in REQUIRED_CONTRACT_FIELDS):
        return "MALFORMED_ADAPTER_CONTRACT"
    if any(field in adapter_contract for field in SENSITIVE_CONTRACT_FIELDS):
        return "SENSITIVE_DATA_REJECTED"
    if adapter_contract.get("execution_status") not in SUPPORTED_ADAPTER_STATES:
        return "UNSUPPORTED_ADAPTER_STATE"
    if adapter_contract.get("execution_status") in {DISABLED, BLOCKED, UNSUPPORTED, TIMEOUT, FAILED}:
        return "ADAPTER_NOT_READY"
    if adapter_contract.get("expected_version") != adapter_contract.get("observed_version"):
        return "ADAPTER_INCOMPATIBLE"
    if adapter_contract.get("decision") != "ALLOW":
        return "FINAL_DECISION_NOT_ALLOW"
    if not isinstance(adapter_contract.get("timeout_seconds"), int) or adapter_contract.get("timeout_seconds") <= 0:
        return "TIMEOUT_INVALID"
    for field in ("execution_contract", "approval_reference", "runtime_reference", "dependency_reference", "audit_reference", "evidence_reference"):
        if not _is_hash(adapter_contract.get(field)):
            return "REFERENCE_INVALID"
    return ""


def _precheck_error(prechecks: Mapping[str, Any] | None) -> str:
    if not isinstance(prechecks, Mapping):
        return "PRECHECKS_MISSING"
    for field in REQUIRED_PRECHECKS:
        if prechecks.get(field) is not True:
            return {
                "policy_evaluated": "POLICY_MISSING",
                "approval_valid": "APPROVAL_MISSING",
                "execution_contract_valid": "EXECUTION_CONTRACT_MISSING",
                "capability_authorized": "CAPABILITY_DENIED",
                "target_policy_valid": "TARGET_NOT_ALLOWED",
                "dependency_ready": "DEPENDENCY_NOT_READY",
                "runtime_ready": "RUNTIME_NOT_READY",
                "replay_protection_passed": "REPLAY_DETECTED",
                "nonce_valid": "NONCE_INVALID",
                "timestamp_window_valid": "TIMESTAMP_INVALID",
                "parameters_valid": "PARAMETERS_INVALID",
                "evidence_destination_ready": "AUDIT_DESTINATION_UNAVAILABLE",
            }[field]
    return ""


def _adapter_registration_error(
    adapter_contract: Mapping[str, Any],
    adapter_registry: Mapping[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]],
) -> str:
    adapter_id = str(adapter_contract.get("adapter_id", ""))
    if adapter_id not in SUPPORTED_ADAPTERS:
        return "UNSUPPORTED_ADAPTER"
    if adapter_id not in adapter_registry:
        return "ADAPTER_UNAVAILABLE"
    if adapter_contract.get("execution_status") != READY:
        return "ADAPTER_NOT_READY"
    return ""


def _blocked(reason_code: str, adapter_id: str, adapter_state: str, contract_hash: str, adapter_result_hash: str) -> AdapterExecutionDecision:
    evidence_hash = sha256_reference(
        {
            "adapter_id": adapter_id,
            "adapter_state": adapter_state,
            "adapter_result_hash": adapter_result_hash,
            "contract_hash": contract_hash,
            "reason_code": reason_code,
        }
    )
    return AdapterExecutionDecision(
        decision=DECISION_BLOCKED,
        reason_code=reason_code,
        adapter_id=adapter_id,
        adapter_state=adapter_state,
        contract_hash=contract_hash,
        evidence_hash=evidence_hash,
        adapter_result_hash=adapter_result_hash,
    )


def _adapter_id(adapter_contract: Mapping[str, Any] | None) -> str:
    if not isinstance(adapter_contract, Mapping):
        return ""
    value = adapter_contract.get("adapter_id")
    return value if isinstance(value, str) else ""


def _adapter_state(adapter_contract: Mapping[str, Any] | None) -> str:
    if not isinstance(adapter_contract, Mapping):
        return ""
    value = adapter_contract.get("execution_status")
    return value if isinstance(value, str) else ""


def _contract_hash(adapter_contract: Mapping[str, Any] | None) -> str:
    if not isinstance(adapter_contract, Mapping):
        return sha256_reference({})
    return sha256_reference(_redacted_contract(adapter_contract))


def _redacted_contract(adapter_contract: Mapping[str, Any]) -> dict[str, Any]:
    return {field: adapter_contract.get(field, "") for field in REQUIRED_CONTRACT_FIELDS if field not in SENSITIVE_CONTRACT_FIELDS}


def _redacted_adapter_result(adapter_result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "execution_status": adapter_result.get("execution_status", ""),
        "adapter_id": adapter_result.get("adapter_id", ""),
        "result_reference": adapter_result.get("result_reference", ""),
    }


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71 and all(char in "0123456789abcdef" for char in value[7:])
