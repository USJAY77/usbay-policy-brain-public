from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.evidence_chain import assert_evidence_chain_safe
from governance.evidence_merkle_checkpoint import (
    MODULE_VERSIONS as CHECKPOINT_MODULE_VERSIONS,
    assert_merkle_safe,
    merkle_checkpoint_summary,
    verify_merkle_checkpoint,
)
from governance.evidence_merkle_consistency import (
    assert_consistency_safe,
    merkle_consistency_summary,
    verify_merkle_consistency_proof,
)
from governance.evidence_merkle_inclusion import (
    assert_inclusion_safe,
    merkle_inclusion_summary,
    verify_merkle_inclusion_proof,
)
from governance.policy_pack import assert_policy_diagnostics_safe, redacted_policy_payload
from governance.policy_parity import assert_parity_diagnostics_safe
from governance.policy_proof_bundle import assert_proof_bundle_safe
from governance.policy_simulation import assert_simulation_diagnostics_safe
from governance.proof_timestamp_anchor import assert_timestamp_anchor_safe
from governance.rfc3161_timestamp import assert_rfc3161_safe
from governance.worm_evidence_manifest import assert_worm_safe

AUDITOR_BUNDLE_SCHEMA = "usbay.governance_auditor_verification_bundle.v1"
AUDITOR_BUNDLE_ERROR_REGISTRY_PATH = Path("governance/auditor_verification_bundle_errors.json")
AUDITOR_BUNDLE_ERROR_SCHEMA = "usbay.governance_auditor_verification_bundle_error_registry.v1"
AUDITOR_BUNDLE_ERROR_CODES = (
    "AUDITOR_BUNDLE_CHECKPOINT_MISSING",
    "AUDITOR_BUNDLE_INCLUSION_MISSING",
    "AUDITOR_BUNDLE_CONSISTENCY_MISSING",
    "AUDITOR_BUNDLE_SCOPE_INVALID",
    "AUDITOR_BUNDLE_HASH_MISMATCH",
    "AUDITOR_BUNDLE_REPLAY_DETECTED",
    "AUDITOR_BUNDLE_DIAGNOSTICS_UNSAFE",
)
MODULE_VERSIONS = {
    **CHECKPOINT_MODULE_VERSIONS,
    "auditor_verification_bundle": AUDITOR_BUNDLE_SCHEMA,
}


class AuditorVerificationBundleError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditorBundleVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    bundle_id: str
    evidence_chain_head_hash: str
    checkpoint_id: str
    merkle_root: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "bundle_id": self.bundle_id,
            "evidence_chain_head_hash": self.evidence_chain_head_hash,
            "checkpoint_id": self.checkpoint_id,
            "merkle_root": self.merkle_root,
            "retention_policy_label": self.retention_policy_label,
        }


def load_auditor_bundle_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / AUDITOR_BUNDLE_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AuditorVerificationBundleError("auditor_bundle_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != AUDITOR_BUNDLE_ERROR_SCHEMA:
        raise AuditorVerificationBundleError("auditor_bundle_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise AuditorVerificationBundleError("auditor_bundle_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise AuditorVerificationBundleError("auditor_bundle_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(AUDITOR_BUNDLE_ERROR_CODES) - set(registry))
    if missing:
        raise AuditorVerificationBundleError("auditor_bundle_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_auditor_verification_bundle(
    checkpoint: dict[str, Any],
    inclusion_proof: dict[str, Any],
    consistency_proof: dict[str, Any],
    *,
    verification_scope: dict[str, Any],
    timestamp: str | None = None,
) -> dict[str, Any]:
    checkpoint_verification = verify_merkle_checkpoint(checkpoint)
    inclusion_verification = verify_merkle_inclusion_proof(inclusion_proof, checkpoint=checkpoint)
    consistency_verification = verify_merkle_consistency_proof(consistency_proof, current_checkpoint=checkpoint)
    if not checkpoint_verification.valid:
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_CHECKPOINT_MISSING")
    if not inclusion_verification.valid:
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_INCLUSION_MISSING")
    if not consistency_verification.valid:
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_CONSISTENCY_MISSING")
    if not _scope_valid(verification_scope):
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_SCOPE_INVALID")
    _validate_cross_bindings(checkpoint_verification, inclusion_verification, consistency_verification)
    timestamp_value = timestamp or _utc_now()
    if not _timestamp_is_valid(timestamp_value):
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_SCOPE_INVALID")
    payload = {
        "checkpoint_id": checkpoint_verification.checkpoint_id,
        "consistency_proof_summary": merkle_consistency_summary(consistency_proof),
        "evidence_chain_head_hash": checkpoint_verification.evidence_chain_head_hash,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "inclusion_proof_summary": merkle_inclusion_summary(inclusion_proof),
        "merkle_root": checkpoint_verification.merkle_root,
        "retention_policy_label": checkpoint_verification.retention_policy_label,
        "utc_timestamp": timestamp_value,
        "verification_scope": dict(sorted(verification_scope.items())),
    }
    bundle = {
        "schema": AUDITOR_BUNDLE_SCHEMA,
        "bundle_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        **payload,
    }
    _assert_auditor_bundle_safe(bundle)
    return bundle


def create_auditor_verification_bundle_file(
    checkpoint_path: Path,
    inclusion_proof_path: Path,
    consistency_proof_path: Path,
    output_path: Path,
    *,
    verification_scope: dict[str, Any],
    timestamp: str | None = None,
) -> dict[str, Any]:
    bundle = create_auditor_verification_bundle(
        _load_json_object(checkpoint_path, "AUDITOR_BUNDLE_CHECKPOINT_MISSING"),
        _load_json_object(inclusion_proof_path, "AUDITOR_BUNDLE_INCLUSION_MISSING"),
        _load_json_object(consistency_proof_path, "AUDITOR_BUNDLE_CONSISTENCY_MISSING"),
        verification_scope=verification_scope,
        timestamp=timestamp,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(bundle) + "\n", encoding="utf-8")
    return bundle


def verify_auditor_verification_bundle(
    bundle: dict[str, Any],
    *,
    existing_bundles: list[dict[str, Any]] | None = None,
) -> AuditorBundleVerificationResult:
    errors: list[str] = []
    if not isinstance(bundle, dict) or bundle.get("schema") != AUDITOR_BUNDLE_SCHEMA:
        errors.append("AUDITOR_BUNDLE_HASH_MISMATCH")
    bundle_id = str(bundle.get("bundle_id", "")) if isinstance(bundle, dict) else ""
    chain_head = str(bundle.get("evidence_chain_head_hash", "")) if isinstance(bundle, dict) else ""
    checkpoint_id = str(bundle.get("checkpoint_id", "")) if isinstance(bundle, dict) else ""
    merkle_root = str(bundle.get("merkle_root", "")) if isinstance(bundle, dict) else ""
    retention_policy_label = str(bundle.get("retention_policy_label", "")) if isinstance(bundle, dict) else ""
    inclusion_summary = bundle.get("inclusion_proof_summary") if isinstance(bundle, dict) else None
    consistency_summary = bundle.get("consistency_proof_summary") if isinstance(bundle, dict) else None
    scope = bundle.get("verification_scope") if isinstance(bundle, dict) else None
    if not _summary_valid(inclusion_summary):
        errors.append("AUDITOR_BUNDLE_INCLUSION_MISSING")
        inclusion_summary = {}
    if not _summary_valid(consistency_summary):
        errors.append("AUDITOR_BUNDLE_CONSISTENCY_MISSING")
        consistency_summary = {}
    if not _is_sha256_hex(checkpoint_id) or not _is_sha256_hex(merkle_root) or not _is_sha256_hex(chain_head) or not retention_policy_label:
        errors.append("AUDITOR_BUNDLE_CHECKPOINT_MISSING")
    if not _scope_valid(scope):
        errors.append("AUDITOR_BUNDLE_SCOPE_INVALID")
    if _summary_valid(inclusion_summary) and (
        inclusion_summary.get("checkpoint_id") != checkpoint_id
        or inclusion_summary.get("merkle_root") != merkle_root
        or inclusion_summary.get("evidence_chain_head_hash") != chain_head
        or inclusion_summary.get("valid") is not True
    ):
        errors.append("AUDITOR_BUNDLE_HASH_MISMATCH")
    if _summary_valid(consistency_summary) and (
        consistency_summary.get("current_checkpoint_id") != checkpoint_id
        or consistency_summary.get("current_merkle_root") != merkle_root
        or consistency_summary.get("evidence_chain_head_hash") != chain_head
        or consistency_summary.get("valid") is not True
    ):
        errors.append("AUDITOR_BUNDLE_HASH_MISMATCH")
    payload = {
        "checkpoint_id": checkpoint_id,
        "consistency_proof_summary": consistency_summary if isinstance(consistency_summary, dict) else {},
        "evidence_chain_head_hash": chain_head,
        "governance_module_versions": bundle.get("governance_module_versions", {}) if isinstance(bundle, dict) else {},
        "inclusion_proof_summary": inclusion_summary if isinstance(inclusion_summary, dict) else {},
        "merkle_root": merkle_root,
        "retention_policy_label": retention_policy_label,
        "utc_timestamp": bundle.get("utc_timestamp", "") if isinstance(bundle, dict) else "",
        "verification_scope": scope if isinstance(scope, dict) else {},
    }
    if not _timestamp_is_valid(str(payload["utc_timestamp"])):
        errors.append("AUDITOR_BUNDLE_SCOPE_INVALID")
    if not _is_sha256_hex(bundle_id) or bundle_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("AUDITOR_BUNDLE_HASH_MISMATCH")
    for existing in existing_bundles or []:
        if isinstance(existing, dict) and existing.get("bundle_id") == bundle_id:
            errors.append("AUDITOR_BUNDLE_REPLAY_DETECTED")
    try:
        _assert_auditor_bundle_safe(bundle)
    except AuditorVerificationBundleError:
        errors.append("AUDITOR_BUNDLE_DIAGNOSTICS_UNSAFE")
    return AuditorBundleVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        bundle_id=bundle_id,
        evidence_chain_head_hash=chain_head,
        checkpoint_id=checkpoint_id,
        merkle_root=merkle_root,
        retention_policy_label=retention_policy_label,
    )


def verify_auditor_verification_bundle_file(
    bundle_path: Path,
    *,
    existing_bundle_paths: list[Path] | None = None,
) -> AuditorBundleVerificationResult:
    existing = [_load_json_object(path, "auditor_bundle_existing_invalid") for path in existing_bundle_paths or []]
    return verify_auditor_verification_bundle(
        _load_json_object(bundle_path, "auditor_bundle_invalid"),
        existing_bundles=existing,
    )


def explain_auditor_bundle_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_auditor_bundle_error_registry(root)
    if code not in registry:
        raise AuditorVerificationBundleError("auditor_bundle_error_unknown:" + code)
    return {"code": code, **registry[code]}


def auditor_bundle_summary(bundle: dict[str, Any]) -> dict[str, Any]:
    verification = verify_auditor_verification_bundle(bundle)
    return verification.to_dict()


def redacted_auditor_bundle_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_auditor_bundle_safe(payload: Any) -> None:
    _assert_auditor_bundle_safe(payload)


def _validate_cross_bindings(checkpoint: Any, inclusion: Any, consistency: Any) -> None:
    if inclusion.checkpoint_id != checkpoint.checkpoint_id or inclusion.merkle_root != checkpoint.merkle_root:
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_HASH_MISMATCH")
    if inclusion.evidence_chain_head_hash != checkpoint.evidence_chain_head_hash:
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_HASH_MISMATCH")
    if consistency.current_checkpoint_id != checkpoint.checkpoint_id or consistency.current_merkle_root != checkpoint.merkle_root:
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_HASH_MISMATCH")
    if consistency.evidence_chain_head_hash != checkpoint.evidence_chain_head_hash:
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_HASH_MISMATCH")


def _summary_valid(summary: Any) -> bool:
    return isinstance(summary, dict) and summary.get("valid") is True and isinstance(summary.get("error_codes"), list) and not summary.get("error_codes")


def _scope_valid(scope: Any) -> bool:
    if not isinstance(scope, dict) or not scope:
        return False
    allowed = {"tenant_id", "environment", "purpose", "auditor_id"}
    if any(key not in allowed or not isinstance(value, str) or not value.strip() for key, value in scope.items()):
        return False
    return "purpose" in scope


def _assert_auditor_bundle_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_policy_diagnostics_safe(redacted)
        assert_simulation_diagnostics_safe(redacted)
        assert_parity_diagnostics_safe(redacted)
        assert_proof_bundle_safe(redacted)
        assert_timestamp_anchor_safe(redacted)
        assert_rfc3161_safe(redacted)
        assert_worm_safe(redacted)
        assert_evidence_chain_safe(redacted)
        assert_merkle_safe(redacted)
        assert_inclusion_safe(redacted)
        assert_consistency_safe(redacted)
        if redacted != payload:
            raise AuditorVerificationBundleError("AUDITOR_BUNDLE_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, AuditorVerificationBundleError):
            raise
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise AuditorVerificationBundleError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AuditorVerificationBundleError(failure_code) from exc
    if not isinstance(payload, dict):
        raise AuditorVerificationBundleError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise AuditorVerificationBundleError("AUDITOR_BUNDLE_HASH_MISMATCH") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _timestamp_is_valid(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return value.endswith("Z") and parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
