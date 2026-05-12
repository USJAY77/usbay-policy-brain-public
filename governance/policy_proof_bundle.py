from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.policy_pack import (
    assert_policy_diagnostics_safe,
    load_policy_pack,
    policy_pack_summary,
    redacted_policy_payload,
    validate_policy_pack,
)
from governance.policy_parity import (
    PolicyParityError,
    assert_parity_diagnostics_safe,
    parity_summary,
    policy_pack_hash,
    redacted_parity_payload,
    request_context_hash,
    verify_policy_parity,
)
from governance.policy_simulation import assert_simulation_diagnostics_safe

PROOF_BUNDLE_SCHEMA = "usbay.governance_policy_proof_bundle.v1"
PROOF_BUNDLE_ERROR_REGISTRY_PATH = Path("governance/policy_proof_bundle_errors.json")
PROOF_BUNDLE_ERROR_SCHEMA = "usbay.governance_policy_proof_bundle_error_registry.v1"
PROOF_BUNDLE_ERROR_CODES = (
    "PROOF_POLICY_HASH_MISSING",
    "PROOF_CONTEXT_HASH_MISSING",
    "PROOF_PARITY_UNVERIFIED",
    "PROOF_DIAGNOSTICS_UNSAFE",
    "PROOF_BUNDLE_INVALID",
)
MODULE_VERSIONS = {
    "policy_pack": "usbay.governance_policy_pack.v1",
    "policy_simulation": "usbay.governance_policy_simulation.v1",
    "policy_parity": "usbay.governance_policy_parity.v1",
    "policy_proof_bundle": PROOF_BUNDLE_SCHEMA,
}


class PolicyProofBundleError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicyProofBundleVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    policy_pack_hash: str
    request_context_hash: str
    simulation_decision: str
    parity_verified: bool
    bundle_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "policy_pack_hash": self.policy_pack_hash,
            "request_context_hash": self.request_context_hash,
            "simulation_decision": self.simulation_decision,
            "parity_verified": self.parity_verified,
            "bundle_hash": self.bundle_hash,
        }


def load_proof_bundle_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / PROOF_BUNDLE_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyProofBundleError("proof_bundle_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != PROOF_BUNDLE_ERROR_SCHEMA:
        raise PolicyProofBundleError("proof_bundle_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise PolicyProofBundleError("proof_bundle_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise PolicyProofBundleError("proof_bundle_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(PROOF_BUNDLE_ERROR_CODES) - set(registry))
    if missing:
        raise PolicyProofBundleError("proof_bundle_error_registry_incomplete:" + ",".join(missing))
    return registry


def build_policy_proof_bundle(
    policy_pack: dict[str, Any],
    request_context: dict[str, Any],
    runtime_decision_record: dict[str, Any],
    *,
    tenant_id: str,
    environment: str,
    risk_level: str,
    required_human_approval: bool = False,
    validation_timestamp: str | None = None,
) -> dict[str, Any]:
    if not runtime_decision_record.get("policy_hash"):
        raise PolicyProofBundleError("PROOF_POLICY_HASH_MISSING")
    if not runtime_decision_record.get("context_hash"):
        raise PolicyProofBundleError("PROOF_CONTEXT_HASH_MISSING")
    try:
        parity = verify_policy_parity(
            policy_pack,
            request_context,
            runtime_decision_record,
            tenant_id=tenant_id,
            environment=environment,
            risk_level=risk_level,
            required_human_approval=required_human_approval,
        )
    except PolicyParityError as exc:
        raise PolicyProofBundleError("PROOF_PARITY_UNVERIFIED") from exc
    if not parity.valid:
        raise PolicyProofBundleError("PROOF_PARITY_UNVERIFIED")
    validation = validate_policy_pack(policy_pack)
    bundle = {
        "schema": PROOF_BUNDLE_SCHEMA,
        "policy_pack_hash": policy_pack_hash(policy_pack),
        "request_context_hash": request_context_hash(
            request_context,
            tenant_id=tenant_id,
            environment=environment,
            risk_level=risk_level,
            required_human_approval=required_human_approval,
        ),
        "simulation_decision": parity.simulated_decision,
        "runtime_parity_result": parity_summary(parity),
        "fail_closed_status": {
            "enforced": True,
            "required": parity.simulated_decision == "FAIL_CLOSED",
            "reason_codes": list(parity.errors),
        },
        "validation_timestamp": validation_timestamp or _utc_now(),
        "governance_module_versions": dict(MODULE_VERSIONS),
        "redacted_diagnostics_summary": redacted_policy_payload(
            {
                "policy_validation": policy_pack_summary(validation),
                "parity": parity_summary(parity),
                "tenant_id": tenant_id,
                "environment": environment,
                "risk_level": risk_level,
                "human_approval_required": parity.human_approval_required,
            }
        ),
    }
    _assert_bundle_safe(bundle)
    return bundle


def export_policy_proof_bundle_file(
    policy_pack_path: Path,
    request_context_path: Path,
    runtime_decision_path: Path,
    output_path: Path,
    *,
    tenant_id: str,
    environment: str,
    risk_level: str,
    required_human_approval: bool = False,
    validation_timestamp: str | None = None,
) -> dict[str, Any]:
    bundle = build_policy_proof_bundle(
        load_policy_pack(policy_pack_path),
        _load_json_object(request_context_path, "proof_request_context_invalid"),
        _load_json_object(runtime_decision_path, "proof_runtime_decision_invalid"),
        tenant_id=tenant_id,
        environment=environment,
        risk_level=risk_level,
        required_human_approval=required_human_approval,
        validation_timestamp=validation_timestamp,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(bundle) + "\n", encoding="utf-8")
    return bundle


def verify_policy_proof_bundle(bundle: dict[str, Any]) -> PolicyProofBundleVerificationResult:
    errors: list[str] = []
    if not isinstance(bundle, dict) or bundle.get("schema") != PROOF_BUNDLE_SCHEMA:
        errors.append("PROOF_BUNDLE_INVALID")
    policy_hash_value = str(bundle.get("policy_pack_hash", "")) if isinstance(bundle, dict) else ""
    context_hash_value = str(bundle.get("request_context_hash", "")) if isinstance(bundle, dict) else ""
    if not _is_sha256_hex(policy_hash_value):
        errors.append("PROOF_POLICY_HASH_MISSING")
    if not _is_sha256_hex(context_hash_value):
        errors.append("PROOF_CONTEXT_HASH_MISSING")
    parity_payload = bundle.get("runtime_parity_result") if isinstance(bundle, dict) else None
    parity_verified = isinstance(parity_payload, dict) and parity_payload.get("valid") is True
    if not parity_verified:
        errors.append("PROOF_PARITY_UNVERIFIED")
    required_fields = (
        "simulation_decision",
        "fail_closed_status",
        "validation_timestamp",
        "governance_module_versions",
        "redacted_diagnostics_summary",
    )
    for field in required_fields:
        if not isinstance(bundle, dict) or field not in bundle:
            errors.append("PROOF_BUNDLE_INVALID")
            break
    try:
        _assert_bundle_safe(bundle)
    except PolicyProofBundleError:
        errors.append("PROOF_DIAGNOSTICS_UNSAFE")
    return PolicyProofBundleVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        policy_pack_hash=policy_hash_value,
        request_context_hash=context_hash_value,
        simulation_decision=str(bundle.get("simulation_decision", "")) if isinstance(bundle, dict) else "",
        parity_verified=parity_verified,
        bundle_hash=_bundle_hash(bundle) if isinstance(bundle, dict) else "",
    )


def verify_policy_proof_bundle_file(path: Path) -> PolicyProofBundleVerificationResult:
    return verify_policy_proof_bundle(_load_json_object(path, "proof_bundle_invalid"))


def explain_proof_bundle(root: Path, code: str) -> dict[str, str]:
    registry = load_proof_bundle_error_registry(root)
    if code not in registry:
        raise PolicyProofBundleError("proof_bundle_error_unknown:" + code)
    return {"code": code, **registry[code]}


def proof_bundle_summary(bundle: dict[str, Any]) -> dict[str, Any]:
    verification = verify_policy_proof_bundle(bundle)
    return {
        "valid": verification.valid,
        "error_codes": list(verification.errors),
        "policy_pack_hash": verification.policy_pack_hash,
        "request_context_hash": verification.request_context_hash,
        "simulation_decision": verification.simulation_decision,
        "parity_verified": verification.parity_verified,
        "bundle_hash": verification.bundle_hash,
    }


def redacted_proof_bundle_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_proof_bundle_safe(payload: Any) -> None:
    _assert_bundle_safe(payload)


def _assert_bundle_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_policy_diagnostics_safe(redacted)
        assert_simulation_diagnostics_safe(redacted)
        assert_parity_diagnostics_safe(redacted)
        if redacted != payload:
            raise PolicyProofBundleError("PROOF_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, PolicyProofBundleError):
            raise
        raise PolicyProofBundleError("PROOF_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path, failure_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyProofBundleError(failure_code) from exc
    if not isinstance(payload, dict):
        raise PolicyProofBundleError(failure_code)
    return payload


def _bundle_hash(bundle: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(bundle).encode("utf-8")).hexdigest()


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise PolicyProofBundleError("PROOF_BUNDLE_INVALID") from exc


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
