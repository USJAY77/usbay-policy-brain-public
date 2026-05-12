from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.policy_pack import (
    PolicyPackValidationError,
    assert_policy_diagnostics_safe,
    load_policy_pack,
    redacted_policy_payload,
)
from governance.policy_simulation import (
    DECISION_FAIL_CLOSED,
    PolicySimulationResult,
    assert_simulation_diagnostics_safe,
    simulate_policy_decision,
)

PARITY_ERROR_REGISTRY_PATH = Path("governance/policy_parity_errors.json")
PARITY_ERROR_SCHEMA = "usbay.governance_policy_parity_error_registry.v1"
PARITY_ERROR_CODES = (
    "PARITY_DECISION_MISMATCH",
    "PARITY_SCOPE_MISMATCH",
    "PARITY_POLICY_HASH_MISMATCH",
    "PARITY_CONTEXT_DRIFT",
    "PARITY_FAIL_CLOSED_REQUIRED",
)


class PolicyParityError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicyParityResult:
    valid: bool
    errors: tuple[str, ...]
    simulated_decision: str
    runtime_decision: str
    policy_hash: str
    runtime_policy_hash: str
    context_hash: str
    runtime_context_hash: str
    tenant_id: str
    runtime_tenant_id: str
    environment: str
    runtime_environment: str
    matched_policy_ids: tuple[str, ...]
    human_approval_required: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "simulated_decision": self.simulated_decision,
            "runtime_decision": self.runtime_decision,
            "policy_hash": self.policy_hash,
            "runtime_policy_hash": self.runtime_policy_hash,
            "context_hash": self.context_hash,
            "runtime_context_hash": self.runtime_context_hash,
            "tenant_id": self.tenant_id,
            "runtime_tenant_id": self.runtime_tenant_id,
            "environment": self.environment,
            "runtime_environment": self.runtime_environment,
            "matched_policy_ids": list(self.matched_policy_ids),
            "human_approval_required": self.human_approval_required,
        }


def load_parity_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / PARITY_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyParityError("parity_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != PARITY_ERROR_SCHEMA:
        raise PolicyParityError("parity_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise PolicyParityError("parity_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise PolicyParityError("parity_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(PARITY_ERROR_CODES) - set(registry))
    if missing:
        raise PolicyParityError("parity_error_registry_incomplete:" + ",".join(missing))
    return registry


def policy_pack_hash(policy_pack: dict[str, Any]) -> str:
    return _sha256_hex(_canonical_json(policy_pack).encode("utf-8"))


def request_context_hash(
    request_context: dict[str, Any],
    *,
    tenant_id: str,
    environment: str,
    risk_level: str,
    required_human_approval: bool = False,
) -> str:
    context = {
        "environment": environment,
        "request_context": request_context,
        "required_human_approval": bool(required_human_approval),
        "risk_level": risk_level,
        "tenant_id": tenant_id,
    }
    return _sha256_hex(_canonical_json(context).encode("utf-8"))


def build_runtime_decision_record(
    *,
    decision: str,
    policy_pack: dict[str, Any],
    request_context: dict[str, Any],
    tenant_id: str,
    environment: str,
    risk_level: str,
    required_human_approval: bool = False,
) -> dict[str, Any]:
    return {
        "decision": decision,
        "policy_hash": policy_pack_hash(policy_pack),
        "context_hash": request_context_hash(
            request_context,
            tenant_id=tenant_id,
            environment=environment,
            risk_level=risk_level,
            required_human_approval=required_human_approval,
        ),
        "tenant_id": tenant_id,
        "environment": environment,
    }


def verify_policy_parity(
    policy_pack: dict[str, Any],
    request_context: dict[str, Any],
    runtime_decision_record: dict[str, Any],
    *,
    tenant_id: str,
    environment: str,
    risk_level: str,
    required_human_approval: bool = False,
) -> PolicyParityResult:
    if not isinstance(runtime_decision_record, dict):
        raise PolicyParityError("runtime_decision_record_invalid")
    simulation = simulate_policy_decision(
        policy_pack,
        request_context,
        tenant_id=tenant_id,
        environment=environment,
        risk_level=risk_level,
        required_human_approval=required_human_approval,
    )
    expected_policy_hash = policy_pack_hash(policy_pack)
    expected_context_hash = request_context_hash(
        request_context,
        tenant_id=tenant_id,
        environment=environment,
        risk_level=risk_level,
        required_human_approval=required_human_approval,
    )
    runtime_decision = str(runtime_decision_record.get("decision", ""))
    runtime_policy_hash = str(runtime_decision_record.get("policy_hash", ""))
    runtime_context_hash = str(runtime_decision_record.get("context_hash", ""))
    runtime_tenant_id = str(runtime_decision_record.get("tenant_id", ""))
    runtime_environment = str(runtime_decision_record.get("environment", ""))
    errors = _parity_errors(
        simulation,
        runtime_decision=runtime_decision,
        expected_policy_hash=expected_policy_hash,
        runtime_policy_hash=runtime_policy_hash,
        expected_context_hash=expected_context_hash,
        runtime_context_hash=runtime_context_hash,
        tenant_id=tenant_id,
        runtime_tenant_id=runtime_tenant_id,
        environment=environment,
        runtime_environment=runtime_environment,
    )
    return PolicyParityResult(
        valid=not errors,
        errors=tuple(errors),
        simulated_decision=simulation.decision,
        runtime_decision=runtime_decision,
        policy_hash=expected_policy_hash,
        runtime_policy_hash=runtime_policy_hash,
        context_hash=expected_context_hash,
        runtime_context_hash=runtime_context_hash,
        tenant_id=tenant_id,
        runtime_tenant_id=runtime_tenant_id,
        environment=environment,
        runtime_environment=runtime_environment,
        matched_policy_ids=simulation.matched_policy_ids,
        human_approval_required=simulation.human_approval_required,
    )


def verify_policy_parity_files(
    policy_pack_path: Path,
    request_context_path: Path,
    runtime_decision_path: Path,
    *,
    tenant_id: str,
    environment: str,
    risk_level: str,
    required_human_approval: bool = False,
) -> PolicyParityResult:
    return verify_policy_parity(
        load_policy_pack(policy_pack_path),
        _load_json_object(request_context_path, "parity_request_context_invalid"),
        _load_json_object(runtime_decision_path, "parity_runtime_decision_invalid"),
        tenant_id=tenant_id,
        environment=environment,
        risk_level=risk_level,
        required_human_approval=required_human_approval,
    )


def explain_parity_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_parity_error_registry(root)
    if code not in registry:
        raise PolicyParityError("parity_error_unknown:" + code)
    return {"code": code, **registry[code]}


def parity_summary(result: PolicyParityResult) -> dict[str, Any]:
    return {
        "valid": result.valid,
        "error_codes": list(result.errors),
        "simulated_decision": result.simulated_decision,
        "runtime_decision": result.runtime_decision,
        "policy_hash_match": result.policy_hash == result.runtime_policy_hash,
        "context_hash_match": result.context_hash == result.runtime_context_hash,
        "scope_match": result.tenant_id == result.runtime_tenant_id and result.environment == result.runtime_environment,
        "human_approval_required": result.human_approval_required,
    }


def redacted_parity_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_parity_diagnostics_safe(payload: Any) -> None:
    assert_policy_diagnostics_safe(payload)
    assert_simulation_diagnostics_safe(payload)


def _parity_errors(
    simulation: PolicySimulationResult,
    *,
    runtime_decision: str,
    expected_policy_hash: str,
    runtime_policy_hash: str,
    expected_context_hash: str,
    runtime_context_hash: str,
    tenant_id: str,
    runtime_tenant_id: str,
    environment: str,
    runtime_environment: str,
) -> list[str]:
    errors: list[str] = []
    if runtime_tenant_id != tenant_id or runtime_environment != environment:
        errors.append("PARITY_SCOPE_MISMATCH")
    if runtime_policy_hash != expected_policy_hash:
        errors.append("PARITY_POLICY_HASH_MISMATCH")
    if runtime_context_hash != expected_context_hash:
        errors.append("PARITY_CONTEXT_DRIFT")
    if simulation.decision == DECISION_FAIL_CLOSED and runtime_decision != DECISION_FAIL_CLOSED:
        errors.append("PARITY_FAIL_CLOSED_REQUIRED")
    if runtime_decision != simulation.decision:
        errors.append("PARITY_DECISION_MISMATCH")
    return list(dict.fromkeys(errors))


def _load_json_object(path: Path, failure_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyParityError(failure_code) from exc
    if not isinstance(payload, dict):
        raise PolicyParityError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise PolicyParityError("parity_canonicalization_failed") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
