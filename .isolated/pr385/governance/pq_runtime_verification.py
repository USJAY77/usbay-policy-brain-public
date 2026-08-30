from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.evidence_pq_renewal_plan import (
    ALLOWED_HASH_ALGORITHMS,
    ALLOWED_TARGET_SIGNATURE_FAMILIES,
    MODULE_VERSIONS as PQ_RENEWAL_PLAN_MODULE_VERSIONS,
    assert_pq_renewal_plan_safe,
    verify_pq_renewal_plan,
)
from governance.policy_pack import redacted_policy_payload

PQ_RUNTIME_VERIFICATION_SCHEMA = "usbay.governance_pq_runtime_verification.v1"
PQ_RUNTIME_VERIFICATION_ERROR_REGISTRY_PATH = Path("governance/pq_runtime_verification_errors.json")
PQ_RUNTIME_VERIFICATION_ERROR_SCHEMA = "usbay.governance_pq_runtime_verification_error_registry.v1"
PQ_RUNTIME_VERIFICATION_ERROR_CODES = (
    "PQ_RUNTIME_PLAN_MISSING",
    "PQ_RUNTIME_POLICY_MISSING",
    "PQ_RUNTIME_POLICY_DENIED",
    "PQ_RUNTIME_VERIFIER_MODE_INVALID",
    "PQ_RUNTIME_SIGNATURE_FAMILY_INVALID",
    "PQ_RUNTIME_HASH_ALGORITHM_INVALID",
    "PQ_RUNTIME_REPLAY_DETECTED",
    "PQ_RUNTIME_APPEND_ONLY_VIOLATION",
    "PQ_RUNTIME_DIAGNOSTICS_UNSAFE",
)
ALLOWED_VERIFIER_MODES = {"STUB_ONLY"}
ALLOWED_POLICY_DECISIONS = {"ALLOW", "DENY"}
MODULE_VERSIONS = {
    **PQ_RENEWAL_PLAN_MODULE_VERSIONS,
    "pq_runtime_verification": PQ_RUNTIME_VERIFICATION_SCHEMA,
}


class PQRuntimeVerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PQRuntimeVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    pq_runtime_verification_id: str
    pq_renewal_plan_id: str
    evidence_record_id: str
    sealed_archive_id: str
    target_signature_family: str
    target_hash_algorithm: str
    verifier_mode: str
    policy_decision: str
    append_only_position: int
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "pq_runtime_verification_id": self.pq_runtime_verification_id,
            "pq_renewal_plan_id": self.pq_renewal_plan_id,
            "evidence_record_id": self.evidence_record_id,
            "sealed_archive_id": self.sealed_archive_id,
            "target_signature_family": self.target_signature_family,
            "target_hash_algorithm": self.target_hash_algorithm,
            "verifier_mode": self.verifier_mode,
            "policy_decision": self.policy_decision,
            "append_only_position": self.append_only_position,
            "retention_policy_label": self.retention_policy_label,
        }


def load_pq_runtime_verification_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / PQ_RUNTIME_VERIFICATION_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PQRuntimeVerificationError("pq_runtime_verification_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != PQ_RUNTIME_VERIFICATION_ERROR_SCHEMA:
        raise PQRuntimeVerificationError("pq_runtime_verification_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise PQRuntimeVerificationError("pq_runtime_verification_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise PQRuntimeVerificationError("pq_runtime_verification_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(PQ_RUNTIME_VERIFICATION_ERROR_CODES) - set(registry))
    if missing:
        raise PQRuntimeVerificationError("pq_runtime_verification_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_pq_runtime_verification(
    pq_renewal_plan: dict[str, Any],
    *,
    verifier_mode: str = "STUB_ONLY",
    policy_decision_id: str,
    policy_decision: str,
    fail_closed_reason: str = "pq_runtime_stub_requires_governance_allow",
    validation_policy_id: str,
) -> dict[str, Any]:
    plan_verification = verify_pq_renewal_plan(pq_renewal_plan)
    if not plan_verification.valid:
        raise PQRuntimeVerificationError("PQ_RUNTIME_PLAN_MISSING")
    decision = _normalize_policy_decision(policy_decision)
    if not _sha256_valid(policy_decision_id):
        raise PQRuntimeVerificationError("PQ_RUNTIME_POLICY_MISSING")
    if decision != "ALLOW":
        raise PQRuntimeVerificationError("PQ_RUNTIME_POLICY_DENIED")
    if verifier_mode != "STUB_ONLY":
        raise PQRuntimeVerificationError("PQ_RUNTIME_VERIFIER_MODE_INVALID")
    if plan_verification.target_signature_family not in ALLOWED_TARGET_SIGNATURE_FAMILIES:
        raise PQRuntimeVerificationError("PQ_RUNTIME_SIGNATURE_FAMILY_INVALID")
    if plan_verification.target_hash_algorithm not in ALLOWED_HASH_ALGORITHMS:
        raise PQRuntimeVerificationError("PQ_RUNTIME_HASH_ALGORITHM_INVALID")
    if validation_policy_id != str(pq_renewal_plan.get("validation_policy_id", "")) or not _policy_valid(validation_policy_id):
        raise PQRuntimeVerificationError("PQ_RUNTIME_POLICY_MISSING")
    if not _reason_valid(fail_closed_reason):
        raise PQRuntimeVerificationError("PQ_RUNTIME_POLICY_MISSING")
    append_only_position = plan_verification.append_only_position
    replay_binding_hash = _replay_binding_hash(
        pq_renewal_plan_id=plan_verification.pq_renewal_plan_id,
        policy_decision_id=policy_decision_id,
        verifier_mode=verifier_mode,
        append_only_position=append_only_position,
        validation_policy_id=validation_policy_id,
    )
    payload = {
        "append_only_position": append_only_position,
        "evidence_record_id": plan_verification.evidence_record_id,
        "fail_closed_reason": fail_closed_reason,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "policy_decision": decision,
        "policy_decision_id": policy_decision_id,
        "pq_renewal_plan_id": plan_verification.pq_renewal_plan_id,
        "replay_binding_hash": replay_binding_hash,
        "retention_policy_label": plan_verification.retention_policy_label,
        "sealed_archive_id": plan_verification.sealed_archive_id,
        "target_hash_algorithm": plan_verification.target_hash_algorithm,
        "target_signature_family": plan_verification.target_signature_family,
        "validation_policy_id": validation_policy_id,
        "verifier_mode": verifier_mode,
    }
    record = {
        "schema": PQ_RUNTIME_VERIFICATION_SCHEMA,
        "pq_runtime_verification_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        **payload,
    }
    _assert_runtime_safe(record)
    return record


def create_pq_runtime_verification_file(
    pq_renewal_plan_path: Path,
    output_path: Path,
    *,
    verifier_mode: str = "STUB_ONLY",
    policy_decision_id: str,
    policy_decision: str,
    fail_closed_reason: str = "pq_runtime_stub_requires_governance_allow",
    validation_policy_id: str,
) -> dict[str, Any]:
    record = create_pq_runtime_verification(
        _load_json_object(pq_renewal_plan_path, "PQ_RUNTIME_PLAN_MISSING"),
        verifier_mode=verifier_mode,
        policy_decision_id=policy_decision_id,
        policy_decision=policy_decision,
        fail_closed_reason=fail_closed_reason,
        validation_policy_id=validation_policy_id,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(record) + "\n", encoding="utf-8")
    return record


def verify_pq_runtime_verification(
    record: dict[str, Any],
    *,
    pq_renewal_plan: dict[str, Any] | None = None,
    existing_records: list[dict[str, Any]] | None = None,
) -> PQRuntimeVerificationResult:
    errors: list[str] = []
    if not isinstance(record, dict) or record.get("schema") != PQ_RUNTIME_VERIFICATION_SCHEMA:
        errors.append("PQ_RUNTIME_PLAN_MISSING")
    runtime_id = str(record.get("pq_runtime_verification_id", "")) if isinstance(record, dict) else ""
    plan_id = str(record.get("pq_renewal_plan_id", "")) if isinstance(record, dict) else ""
    evidence_record_id = str(record.get("evidence_record_id", "")) if isinstance(record, dict) else ""
    sealed_archive_id = str(record.get("sealed_archive_id", "")) if isinstance(record, dict) else ""
    target_signature_family = str(record.get("target_signature_family", "")) if isinstance(record, dict) else ""
    target_hash_algorithm = str(record.get("target_hash_algorithm", "")) if isinstance(record, dict) else ""
    verifier_mode = str(record.get("verifier_mode", "")) if isinstance(record, dict) else ""
    policy_decision_id = str(record.get("policy_decision_id", "")) if isinstance(record, dict) else ""
    policy_decision = _normalize_policy_decision(str(record.get("policy_decision", "")) if isinstance(record, dict) else "")
    fail_closed_reason = str(record.get("fail_closed_reason", "")) if isinstance(record, dict) else ""
    replay_binding_hash = str(record.get("replay_binding_hash", "")) if isinstance(record, dict) else ""
    append_only_position = record.get("append_only_position") if isinstance(record, dict) else None
    validation_policy_id = str(record.get("validation_policy_id", "")) if isinstance(record, dict) else ""
    retention_policy_label = str(record.get("retention_policy_label", "")) if isinstance(record, dict) else ""
    if not _sha256_valid(plan_id) or not _sha256_valid(evidence_record_id) or not _sha256_valid(sealed_archive_id):
        errors.append("PQ_RUNTIME_PLAN_MISSING")
    if not _sha256_valid(policy_decision_id):
        errors.append("PQ_RUNTIME_POLICY_MISSING")
    if policy_decision not in ALLOWED_POLICY_DECISIONS:
        errors.append("PQ_RUNTIME_POLICY_MISSING")
    elif policy_decision != "ALLOW":
        errors.append("PQ_RUNTIME_POLICY_DENIED")
    if verifier_mode not in ALLOWED_VERIFIER_MODES:
        errors.append("PQ_RUNTIME_VERIFIER_MODE_INVALID")
    if target_signature_family not in ALLOWED_TARGET_SIGNATURE_FAMILIES:
        errors.append("PQ_RUNTIME_SIGNATURE_FAMILY_INVALID")
    if target_hash_algorithm not in ALLOWED_HASH_ALGORITHMS:
        errors.append("PQ_RUNTIME_HASH_ALGORITHM_INVALID")
    if not isinstance(append_only_position, int) or append_only_position < 1:
        errors.append("PQ_RUNTIME_APPEND_ONLY_VIOLATION")
    if not _policy_valid(validation_policy_id) or not _reason_valid(fail_closed_reason):
        errors.append("PQ_RUNTIME_POLICY_MISSING")
    expected_replay = _replay_binding_hash(
        pq_renewal_plan_id=plan_id,
        policy_decision_id=policy_decision_id,
        verifier_mode=verifier_mode,
        append_only_position=append_only_position if isinstance(append_only_position, int) else -1,
        validation_policy_id=validation_policy_id,
    )
    if replay_binding_hash != expected_replay:
        errors.append("PQ_RUNTIME_APPEND_ONLY_VIOLATION")
    payload = _runtime_payload(record)
    if not _sha256_valid(runtime_id) or runtime_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("PQ_RUNTIME_APPEND_ONLY_VIOLATION")
    if pq_renewal_plan is not None:
        plan_verification = verify_pq_renewal_plan(pq_renewal_plan)
        if (
            not plan_verification.valid
            or plan_verification.pq_renewal_plan_id != plan_id
            or plan_verification.evidence_record_id != evidence_record_id
            or plan_verification.sealed_archive_id != sealed_archive_id
            or plan_verification.target_signature_family != target_signature_family
            or plan_verification.target_hash_algorithm != target_hash_algorithm
            or plan_verification.retention_policy_label != retention_policy_label
            or str(pq_renewal_plan.get("validation_policy_id", "")) != validation_policy_id
        ):
            errors.append("PQ_RUNTIME_PLAN_MISSING")
        elif plan_verification.append_only_position != append_only_position:
            errors.append("PQ_RUNTIME_APPEND_ONLY_VIOLATION")
    for existing in existing_records or []:
        if isinstance(existing, dict) and existing.get("pq_runtime_verification_id") == runtime_id:
            errors.append("PQ_RUNTIME_REPLAY_DETECTED")
    try:
        _assert_runtime_safe(record)
    except PQRuntimeVerificationError:
        errors.append("PQ_RUNTIME_DIAGNOSTICS_UNSAFE")
    return PQRuntimeVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        pq_runtime_verification_id=runtime_id,
        pq_renewal_plan_id=plan_id,
        evidence_record_id=evidence_record_id,
        sealed_archive_id=sealed_archive_id,
        target_signature_family=target_signature_family,
        target_hash_algorithm=target_hash_algorithm,
        verifier_mode=verifier_mode,
        policy_decision=policy_decision,
        append_only_position=append_only_position if isinstance(append_only_position, int) else -1,
        retention_policy_label=retention_policy_label,
    )


def verify_pq_runtime_verification_file(
    runtime_verification_path: Path,
    *,
    pq_renewal_plan_path: Path | None = None,
    existing_runtime_verification_paths: list[Path] | None = None,
) -> PQRuntimeVerificationResult:
    existing = [_load_json_object(path, "pq_runtime_verification_existing_invalid") for path in existing_runtime_verification_paths or []]
    return verify_pq_runtime_verification(
        _load_json_object(runtime_verification_path, "pq_runtime_verification_invalid"),
        pq_renewal_plan=_load_json_object(pq_renewal_plan_path, "PQ_RUNTIME_PLAN_MISSING") if pq_renewal_plan_path else None,
        existing_records=existing,
    )


def explain_pq_runtime_verification_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_pq_runtime_verification_error_registry(root)
    if code not in registry:
        raise PQRuntimeVerificationError("pq_runtime_verification_error_unknown:" + code)
    return {"code": code, **registry[code]}


def pq_runtime_verification_summary(record: dict[str, Any]) -> dict[str, Any]:
    return verify_pq_runtime_verification(record).to_dict()


def redacted_pq_runtime_verification_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_pq_runtime_verification_safe(payload: Any) -> None:
    _assert_runtime_safe(payload)


def _runtime_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "append_only_position": record.get("append_only_position", -1),
        "evidence_record_id": record.get("evidence_record_id", ""),
        "fail_closed_reason": record.get("fail_closed_reason", ""),
        "governance_module_versions": record.get("governance_module_versions", {}),
        "policy_decision": _normalize_policy_decision(str(record.get("policy_decision", ""))),
        "policy_decision_id": record.get("policy_decision_id", ""),
        "pq_renewal_plan_id": record.get("pq_renewal_plan_id", ""),
        "replay_binding_hash": record.get("replay_binding_hash", ""),
        "retention_policy_label": record.get("retention_policy_label", ""),
        "sealed_archive_id": record.get("sealed_archive_id", ""),
        "target_hash_algorithm": record.get("target_hash_algorithm", ""),
        "target_signature_family": record.get("target_signature_family", ""),
        "validation_policy_id": record.get("validation_policy_id", ""),
        "verifier_mode": record.get("verifier_mode", ""),
    }


def _replay_binding_hash(
    *,
    pq_renewal_plan_id: str,
    policy_decision_id: str,
    verifier_mode: str,
    append_only_position: int,
    validation_policy_id: str,
) -> str:
    payload = {
        "append_only_position": append_only_position,
        "policy_decision_id": policy_decision_id,
        "pq_renewal_plan_id": pq_renewal_plan_id,
        "validation_policy_id": validation_policy_id,
        "verifier_mode": verifier_mode,
    }
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def _normalize_policy_decision(value: str) -> str:
    return value.strip().upper()


def _policy_valid(value: str) -> bool:
    return bool(value) and all(part.replace("-", "").replace("_", "").isalnum() for part in value.split(".")) and "." in value


def _reason_valid(value: str) -> bool:
    return bool(value) and all(part.replace("-", "").replace("_", "").isalnum() for part in value.split(".")) and len(value) <= 128


def _sha256_valid(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _assert_runtime_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_pq_renewal_plan_safe(redacted)
        if redacted != payload:
            raise PQRuntimeVerificationError("PQ_RUNTIME_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, PQRuntimeVerificationError):
            raise
        raise PQRuntimeVerificationError("PQ_RUNTIME_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise PQRuntimeVerificationError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PQRuntimeVerificationError(failure_code) from exc
    if not isinstance(payload, dict):
        raise PQRuntimeVerificationError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise PQRuntimeVerificationError("PQ_RUNTIME_APPEND_ONLY_VIOLATION") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
