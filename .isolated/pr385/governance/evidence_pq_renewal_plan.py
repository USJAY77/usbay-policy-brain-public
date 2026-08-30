from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.evidence_record_chain import (
    MODULE_VERSIONS as EVIDENCE_RECORD_MODULE_VERSIONS,
    assert_evidence_record_safe,
    verify_evidence_record,
)
from governance.policy_pack import redacted_policy_payload

EVIDENCE_PQ_RENEWAL_PLAN_SCHEMA = "usbay.governance_evidence_pq_renewal_plan.v1"
EVIDENCE_PQ_RENEWAL_PLAN_ERROR_REGISTRY_PATH = Path("governance/evidence_pq_renewal_plan_errors.json")
EVIDENCE_PQ_RENEWAL_PLAN_ERROR_SCHEMA = "usbay.governance_evidence_pq_renewal_plan_error_registry.v1"
EVIDENCE_PQ_RENEWAL_PLAN_ERROR_CODES = (
    "PQ_RENEWAL_EVIDENCE_RECORD_MISSING",
    "PQ_RENEWAL_TARGET_ALGORITHM_INVALID",
    "PQ_RENEWAL_SIGNATURE_FAMILY_INVALID",
    "PQ_RENEWAL_DOWNGRADE_DETECTED",
    "PQ_RENEWAL_APPEND_ONLY_VIOLATION",
    "PQ_RENEWAL_REPLAY_DETECTED",
    "PQ_RENEWAL_POLICY_INVALID",
    "PQ_RENEWAL_DIAGNOSTICS_UNSAFE",
)
ALLOWED_HASH_ALGORITHMS = {"SHA256", "SHA3_512", "SHAKE256_512"}
HASH_ALGORITHM_STRENGTH = {"SHA256": 1, "SHA3_512": 2, "SHAKE256_512": 3}
ALLOWED_TARGET_SIGNATURE_FAMILIES = {"ML_DSA", "SLH_DSA", "HYBRID_ED25519_ML_DSA"}
ALLOWED_CURRENT_SIGNATURE_FAMILIES = {"ED25519"}
MODULE_VERSIONS = {
    **EVIDENCE_RECORD_MODULE_VERSIONS,
    "evidence_pq_renewal_plan": EVIDENCE_PQ_RENEWAL_PLAN_SCHEMA,
}


class EvidencePQRenewalPlanError(RuntimeError):
    pass


@dataclass(frozen=True)
class EvidencePQRenewalPlanVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    pq_renewal_plan_id: str
    evidence_record_id: str
    sealed_archive_id: str
    current_hash_algorithm: str
    target_hash_algorithm: str
    target_signature_family: str
    planned_renewal_round: int
    append_only_position: int
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "pq_renewal_plan_id": self.pq_renewal_plan_id,
            "evidence_record_id": self.evidence_record_id,
            "sealed_archive_id": self.sealed_archive_id,
            "current_hash_algorithm": self.current_hash_algorithm,
            "target_hash_algorithm": self.target_hash_algorithm,
            "target_signature_family": self.target_signature_family,
            "planned_renewal_round": self.planned_renewal_round,
            "append_only_position": self.append_only_position,
            "retention_policy_label": self.retention_policy_label,
        }


def load_pq_renewal_plan_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / EVIDENCE_PQ_RENEWAL_PLAN_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidencePQRenewalPlanError("pq_renewal_plan_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != EVIDENCE_PQ_RENEWAL_PLAN_ERROR_SCHEMA:
        raise EvidencePQRenewalPlanError("pq_renewal_plan_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise EvidencePQRenewalPlanError("pq_renewal_plan_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise EvidencePQRenewalPlanError("pq_renewal_plan_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(EVIDENCE_PQ_RENEWAL_PLAN_ERROR_CODES) - set(registry))
    if missing:
        raise EvidencePQRenewalPlanError("pq_renewal_plan_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_pq_renewal_plan(
    evidence_record: dict[str, Any],
    *,
    target_hash_algorithm: str,
    current_signature_family: str = "ED25519",
    target_signature_family: str,
    migration_reason: str,
    validation_policy_id: str,
) -> dict[str, Any]:
    evidence_verification = verify_evidence_record(evidence_record)
    if not evidence_verification.valid:
        raise EvidencePQRenewalPlanError("PQ_RENEWAL_EVIDENCE_RECORD_MISSING")
    current_hash_algorithm = str(evidence_record.get("hash_algorithm", ""))
    if current_hash_algorithm not in ALLOWED_HASH_ALGORITHMS or target_hash_algorithm not in ALLOWED_HASH_ALGORITHMS:
        raise EvidencePQRenewalPlanError("PQ_RENEWAL_TARGET_ALGORITHM_INVALID")
    if HASH_ALGORITHM_STRENGTH[target_hash_algorithm] <= HASH_ALGORITHM_STRENGTH[current_hash_algorithm]:
        raise EvidencePQRenewalPlanError("PQ_RENEWAL_DOWNGRADE_DETECTED")
    if current_signature_family not in ALLOWED_CURRENT_SIGNATURE_FAMILIES or target_signature_family not in ALLOWED_TARGET_SIGNATURE_FAMILIES:
        raise EvidencePQRenewalPlanError("PQ_RENEWAL_SIGNATURE_FAMILY_INVALID")
    if not _policy_valid(validation_policy_id) or not _reason_valid(migration_reason):
        raise EvidencePQRenewalPlanError("PQ_RENEWAL_POLICY_INVALID")
    planned_round = evidence_verification.renewal_round + 1
    append_only_position = evidence_verification.append_only_position + 1
    replay_binding_hash = _replay_binding_hash(
        evidence_record_id=evidence_verification.evidence_record_id,
        sealed_archive_id=evidence_verification.sealed_archive_id,
        target_hash_algorithm=target_hash_algorithm,
        target_signature_family=target_signature_family,
        planned_renewal_round=planned_round,
        append_only_position=append_only_position,
        validation_policy_id=validation_policy_id,
    )
    payload = {
        "append_only_position": append_only_position,
        "current_hash_algorithm": current_hash_algorithm,
        "current_signature_family": current_signature_family,
        "evidence_record_id": evidence_verification.evidence_record_id,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "migration_reason": migration_reason,
        "planned_renewal_round": planned_round,
        "replay_binding_hash": replay_binding_hash,
        "retention_policy_label": evidence_verification.retention_policy_label,
        "sealed_archive_id": evidence_verification.sealed_archive_id,
        "target_hash_algorithm": target_hash_algorithm,
        "target_signature_family": target_signature_family,
        "validation_policy_id": validation_policy_id,
    }
    plan = {
        "schema": EVIDENCE_PQ_RENEWAL_PLAN_SCHEMA,
        "pq_renewal_plan_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        **payload,
    }
    _assert_pq_plan_safe(plan)
    return plan


def create_pq_renewal_plan_file(
    evidence_record_path: Path,
    output_path: Path,
    *,
    target_hash_algorithm: str,
    current_signature_family: str = "ED25519",
    target_signature_family: str,
    migration_reason: str,
    validation_policy_id: str,
) -> dict[str, Any]:
    plan = create_pq_renewal_plan(
        _load_json_object(evidence_record_path, "PQ_RENEWAL_EVIDENCE_RECORD_MISSING"),
        target_hash_algorithm=target_hash_algorithm,
        current_signature_family=current_signature_family,
        target_signature_family=target_signature_family,
        migration_reason=migration_reason,
        validation_policy_id=validation_policy_id,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(plan) + "\n", encoding="utf-8")
    return plan


def verify_pq_renewal_plan(
    plan: dict[str, Any],
    *,
    evidence_record: dict[str, Any] | None = None,
    existing_plans: list[dict[str, Any]] | None = None,
) -> EvidencePQRenewalPlanVerificationResult:
    errors: list[str] = []
    if not isinstance(plan, dict) or plan.get("schema") != EVIDENCE_PQ_RENEWAL_PLAN_SCHEMA:
        errors.append("PQ_RENEWAL_EVIDENCE_RECORD_MISSING")
    plan_id = str(plan.get("pq_renewal_plan_id", "")) if isinstance(plan, dict) else ""
    evidence_record_id = str(plan.get("evidence_record_id", "")) if isinstance(plan, dict) else ""
    sealed_archive_id = str(plan.get("sealed_archive_id", "")) if isinstance(plan, dict) else ""
    current_hash_algorithm = str(plan.get("current_hash_algorithm", "")) if isinstance(plan, dict) else ""
    target_hash_algorithm = str(plan.get("target_hash_algorithm", "")) if isinstance(plan, dict) else ""
    current_signature_family = str(plan.get("current_signature_family", "")) if isinstance(plan, dict) else ""
    target_signature_family = str(plan.get("target_signature_family", "")) if isinstance(plan, dict) else ""
    migration_reason = str(plan.get("migration_reason", "")) if isinstance(plan, dict) else ""
    planned_round = plan.get("planned_renewal_round") if isinstance(plan, dict) else None
    append_only_position = plan.get("append_only_position") if isinstance(plan, dict) else None
    replay_binding_hash = str(plan.get("replay_binding_hash", "")) if isinstance(plan, dict) else ""
    validation_policy_id = str(plan.get("validation_policy_id", "")) if isinstance(plan, dict) else ""
    retention_policy_label = str(plan.get("retention_policy_label", "")) if isinstance(plan, dict) else ""
    if not _sha256_valid(evidence_record_id) or not _sha256_valid(sealed_archive_id):
        errors.append("PQ_RENEWAL_EVIDENCE_RECORD_MISSING")
    if current_hash_algorithm not in ALLOWED_HASH_ALGORITHMS or target_hash_algorithm not in ALLOWED_HASH_ALGORITHMS:
        errors.append("PQ_RENEWAL_TARGET_ALGORITHM_INVALID")
    elif HASH_ALGORITHM_STRENGTH[target_hash_algorithm] <= HASH_ALGORITHM_STRENGTH[current_hash_algorithm]:
        errors.append("PQ_RENEWAL_DOWNGRADE_DETECTED")
    if current_signature_family not in ALLOWED_CURRENT_SIGNATURE_FAMILIES or target_signature_family not in ALLOWED_TARGET_SIGNATURE_FAMILIES:
        errors.append("PQ_RENEWAL_SIGNATURE_FAMILY_INVALID")
    if not _policy_valid(validation_policy_id) or not _reason_valid(migration_reason):
        errors.append("PQ_RENEWAL_POLICY_INVALID")
    if not isinstance(planned_round, int) or not isinstance(append_only_position, int) or planned_round < 1 or append_only_position < 1:
        errors.append("PQ_RENEWAL_APPEND_ONLY_VIOLATION")
    expected_replay = _replay_binding_hash(
        evidence_record_id=evidence_record_id,
        sealed_archive_id=sealed_archive_id,
        target_hash_algorithm=target_hash_algorithm,
        target_signature_family=target_signature_family,
        planned_renewal_round=planned_round if isinstance(planned_round, int) else -1,
        append_only_position=append_only_position if isinstance(append_only_position, int) else -1,
        validation_policy_id=validation_policy_id,
    )
    if replay_binding_hash != expected_replay:
        errors.append("PQ_RENEWAL_APPEND_ONLY_VIOLATION")
    payload = _plan_payload(plan)
    if not _sha256_valid(plan_id) or plan_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("PQ_RENEWAL_APPEND_ONLY_VIOLATION")
    if evidence_record is not None:
        evidence_verification = verify_evidence_record(evidence_record)
        if (
            not evidence_verification.valid
            or evidence_verification.evidence_record_id != evidence_record_id
            or evidence_verification.sealed_archive_id != sealed_archive_id
            or evidence_verification.retention_policy_label != retention_policy_label
            or evidence_record.get("hash_algorithm") != current_hash_algorithm
        ):
            errors.append("PQ_RENEWAL_EVIDENCE_RECORD_MISSING")
        elif planned_round != evidence_verification.renewal_round + 1 or append_only_position != evidence_verification.append_only_position + 1:
            errors.append("PQ_RENEWAL_APPEND_ONLY_VIOLATION")
    for existing in existing_plans or []:
        if isinstance(existing, dict) and existing.get("pq_renewal_plan_id") == plan_id:
            errors.append("PQ_RENEWAL_REPLAY_DETECTED")
    try:
        _assert_pq_plan_safe(plan)
    except EvidencePQRenewalPlanError:
        errors.append("PQ_RENEWAL_DIAGNOSTICS_UNSAFE")
    return EvidencePQRenewalPlanVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        pq_renewal_plan_id=plan_id,
        evidence_record_id=evidence_record_id,
        sealed_archive_id=sealed_archive_id,
        current_hash_algorithm=current_hash_algorithm,
        target_hash_algorithm=target_hash_algorithm,
        target_signature_family=target_signature_family,
        planned_renewal_round=planned_round if isinstance(planned_round, int) else -1,
        append_only_position=append_only_position if isinstance(append_only_position, int) else -1,
        retention_policy_label=retention_policy_label,
    )


def verify_pq_renewal_plan_file(
    plan_path: Path,
    *,
    evidence_record_path: Path | None = None,
    existing_plan_paths: list[Path] | None = None,
) -> EvidencePQRenewalPlanVerificationResult:
    existing = [_load_json_object(path, "pq_renewal_plan_existing_invalid") for path in existing_plan_paths or []]
    return verify_pq_renewal_plan(
        _load_json_object(plan_path, "pq_renewal_plan_invalid"),
        evidence_record=_load_json_object(evidence_record_path, "PQ_RENEWAL_EVIDENCE_RECORD_MISSING") if evidence_record_path else None,
        existing_plans=existing,
    )


def explain_pq_renewal_plan_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_pq_renewal_plan_error_registry(root)
    if code not in registry:
        raise EvidencePQRenewalPlanError("pq_renewal_plan_error_unknown:" + code)
    return {"code": code, **registry[code]}


def pq_renewal_plan_summary(plan: dict[str, Any]) -> dict[str, Any]:
    return verify_pq_renewal_plan(plan).to_dict()


def redacted_pq_renewal_plan_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_pq_renewal_plan_safe(payload: Any) -> None:
    _assert_pq_plan_safe(payload)


def _plan_payload(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "append_only_position": plan.get("append_only_position", -1),
        "current_hash_algorithm": plan.get("current_hash_algorithm", ""),
        "current_signature_family": plan.get("current_signature_family", ""),
        "evidence_record_id": plan.get("evidence_record_id", ""),
        "governance_module_versions": plan.get("governance_module_versions", {}),
        "migration_reason": plan.get("migration_reason", ""),
        "planned_renewal_round": plan.get("planned_renewal_round", -1),
        "replay_binding_hash": plan.get("replay_binding_hash", ""),
        "retention_policy_label": plan.get("retention_policy_label", ""),
        "sealed_archive_id": plan.get("sealed_archive_id", ""),
        "target_hash_algorithm": plan.get("target_hash_algorithm", ""),
        "target_signature_family": plan.get("target_signature_family", ""),
        "validation_policy_id": plan.get("validation_policy_id", ""),
    }


def _replay_binding_hash(
    *,
    evidence_record_id: str,
    sealed_archive_id: str,
    target_hash_algorithm: str,
    target_signature_family: str,
    planned_renewal_round: int,
    append_only_position: int,
    validation_policy_id: str,
) -> str:
    payload = {
        "append_only_position": append_only_position,
        "evidence_record_id": evidence_record_id,
        "planned_renewal_round": planned_renewal_round,
        "sealed_archive_id": sealed_archive_id,
        "target_hash_algorithm": target_hash_algorithm,
        "target_signature_family": target_signature_family,
        "validation_policy_id": validation_policy_id,
    }
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def _policy_valid(value: str) -> bool:
    return bool(value) and all(part.replace("-", "").replace("_", "").isalnum() for part in value.split(".")) and "." in value


def _reason_valid(value: str) -> bool:
    return bool(value) and all(part.replace("-", "").replace("_", "").isalnum() for part in value.split(".")) and len(value) <= 128


def _sha256_valid(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _assert_pq_plan_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_evidence_record_safe(redacted)
        if redacted != payload:
            raise EvidencePQRenewalPlanError("PQ_RENEWAL_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, EvidencePQRenewalPlanError):
            raise
        raise EvidencePQRenewalPlanError("PQ_RENEWAL_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise EvidencePQRenewalPlanError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidencePQRenewalPlanError(failure_code) from exc
    if not isinstance(payload, dict):
        raise EvidencePQRenewalPlanError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise EvidencePQRenewalPlanError("PQ_RENEWAL_APPEND_ONLY_VIOLATION") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
