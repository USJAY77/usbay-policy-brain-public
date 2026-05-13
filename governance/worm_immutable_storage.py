from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.evidence_record_chain import (
    MODULE_VERSIONS as EVIDENCE_RECORD_MODULE_VERSIONS,
    assert_evidence_record_safe,
    verify_evidence_record,
)
from governance.policy_pack import redacted_policy_payload
from governance.sealed_audit_archive import assert_sealed_audit_archive_safe, verify_sealed_audit_archive

WORM_IMMUTABLE_STORAGE_SCHEMA = "usbay.governance_worm_immutable_storage.v1"
WORM_IMMUTABLE_STORAGE_ERROR_REGISTRY_PATH = Path("governance/worm_immutable_storage_errors.json")
WORM_IMMUTABLE_STORAGE_ERROR_SCHEMA = "usbay.governance_worm_immutable_storage_error_registry.v1"
WORM_IMMUTABLE_STORAGE_ERROR_CODES = (
    "WORM_IMMUTABLE_ARCHIVE_ROOT_HASH_MISSING",
    "WORM_IMMUTABLE_EVIDENCE_RECORD_CHAIN_MISSING",
    "WORM_IMMUTABLE_ENTRY_ORDER_INVALID",
    "WORM_IMMUTABLE_DUPLICATE_ARCHIVE_ID",
    "WORM_IMMUTABLE_OUTPUT_PATH_MUTABLE",
    "WORM_IMMUTABLE_MANIFEST_INVALID",
    "WORM_IMMUTABLE_DIAGNOSTICS_UNSAFE",
)
WORM_IMMUTABLE_STORAGE_MODE = "LOCAL_ONLY"
WORM_IMMUTABLE_ARTIFACT_ORDER = ("sealed_audit_archive", "evidence_record_chain")
MODULE_VERSIONS = {
    **EVIDENCE_RECORD_MODULE_VERSIONS,
    "worm_immutable_storage": WORM_IMMUTABLE_STORAGE_SCHEMA,
}


class WORMImmutableStorageError(RuntimeError):
    pass


@dataclass(frozen=True)
class WORMImmutableStorageVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    worm_storage_plan_id: str
    sealed_archive_id: str
    archive_root_hash: str
    evidence_record_id: str
    immutable_storage_manifest_hash: str
    storage_mode: str
    archive_scope: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "worm_storage_plan_id": self.worm_storage_plan_id,
            "sealed_archive_id": self.sealed_archive_id,
            "archive_root_hash": self.archive_root_hash,
            "evidence_record_id": self.evidence_record_id,
            "immutable_storage_manifest_hash": self.immutable_storage_manifest_hash,
            "storage_mode": self.storage_mode,
            "archive_scope": self.archive_scope,
            "retention_policy_label": self.retention_policy_label,
        }


def load_worm_immutable_storage_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / WORM_IMMUTABLE_STORAGE_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise WORMImmutableStorageError("worm_immutable_storage_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != WORM_IMMUTABLE_STORAGE_ERROR_SCHEMA:
        raise WORMImmutableStorageError("worm_immutable_storage_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise WORMImmutableStorageError("worm_immutable_storage_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise WORMImmutableStorageError("worm_immutable_storage_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(WORM_IMMUTABLE_STORAGE_ERROR_CODES) - set(registry))
    if missing:
        raise WORMImmutableStorageError("worm_immutable_storage_error_registry_incomplete:" + ",".join(missing))
    return registry


def prepare_worm_immutable_storage_plan(
    *,
    sealed_archive: dict[str, Any],
    evidence_record_chain: dict[str, Any],
    created_at_utc: str | None = None,
) -> dict[str, Any]:
    archive_verification = verify_sealed_audit_archive(sealed_archive)
    if not archive_verification.valid or not _is_sha256_hex(archive_verification.archive_root_hash):
        raise WORMImmutableStorageError("WORM_IMMUTABLE_ARCHIVE_ROOT_HASH_MISSING")
    record_verification = verify_evidence_record(evidence_record_chain, sealed_archive=sealed_archive)
    if not record_verification.valid or not _is_sha256_hex(record_verification.evidence_record_id):
        raise WORMImmutableStorageError("WORM_IMMUTABLE_EVIDENCE_RECORD_CHAIN_MISSING")
    if record_verification.sealed_archive_id != archive_verification.archive_id or record_verification.archive_root_hash != archive_verification.archive_root_hash:
        raise WORMImmutableStorageError("WORM_IMMUTABLE_EVIDENCE_RECORD_CHAIN_MISSING")
    created_at = created_at_utc or _utc_now()
    if not _timestamp_is_valid(created_at):
        raise WORMImmutableStorageError("WORM_IMMUTABLE_MANIFEST_INVALID")
    entries = _storage_manifest_entries(
        sealed_archive=sealed_archive,
        evidence_record_chain=evidence_record_chain,
        sealed_archive_id=archive_verification.archive_id,
        archive_root_hash=archive_verification.archive_root_hash,
        archive_scope=archive_verification.archive_scope,
    )
    manifest_hash = _storage_manifest_hash(entries)
    payload = {
        "archive_manifest_hash": archive_verification.archive_manifest_hash,
        "archive_root_hash": archive_verification.archive_root_hash,
        "archive_scope": archive_verification.archive_scope,
        "created_at_utc": created_at,
        "evidence_record_chain_hash": record_verification.archive_timestamp_chain_hash,
        "evidence_record_id": record_verification.evidence_record_id,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "immutable_storage_manifest_hash": manifest_hash,
        "retention_policy_label": archive_verification.retention_policy_label,
        "sealed_archive_id": archive_verification.archive_id,
        "storage_mode": WORM_IMMUTABLE_STORAGE_MODE,
    }
    plan = {
        "schema": WORM_IMMUTABLE_STORAGE_SCHEMA,
        "worm_storage_plan_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        "immutable_storage_manifest": entries,
        **payload,
    }
    _assert_worm_immutable_storage_safe(plan)
    return plan


def prepare_worm_immutable_storage_plan_file(
    *,
    sealed_archive_path: Path,
    evidence_record_path: Path,
    output_path: Path,
    created_at_utc: str | None = None,
) -> dict[str, Any]:
    plan = prepare_worm_immutable_storage_plan(
        sealed_archive=_load_json_object(sealed_archive_path, "WORM_IMMUTABLE_ARCHIVE_ROOT_HASH_MISSING"),
        evidence_record_chain=_load_json_object(evidence_record_path, "WORM_IMMUTABLE_EVIDENCE_RECORD_CHAIN_MISSING"),
        created_at_utc=created_at_utc,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(plan) + "\n", encoding="utf-8")
    return plan


def verify_worm_immutable_storage_plan(
    plan: dict[str, Any],
    *,
    sealed_archive: dict[str, Any] | None = None,
    evidence_record_chain: dict[str, Any] | None = None,
    existing_plans: list[dict[str, Any]] | None = None,
) -> WORMImmutableStorageVerificationResult:
    errors: list[str] = []
    if not isinstance(plan, dict) or plan.get("schema") != WORM_IMMUTABLE_STORAGE_SCHEMA:
        errors.append("WORM_IMMUTABLE_MANIFEST_INVALID")
    plan_id = str(plan.get("worm_storage_plan_id", "")) if isinstance(plan, dict) else ""
    sealed_archive_id = str(plan.get("sealed_archive_id", "")) if isinstance(plan, dict) else ""
    archive_root_hash = str(plan.get("archive_root_hash", "")) if isinstance(plan, dict) else ""
    evidence_record_id = str(plan.get("evidence_record_id", "")) if isinstance(plan, dict) else ""
    manifest_hash = str(plan.get("immutable_storage_manifest_hash", "")) if isinstance(plan, dict) else ""
    storage_mode = str(plan.get("storage_mode", "")) if isinstance(plan, dict) else ""
    archive_scope = str(plan.get("archive_scope", "")) if isinstance(plan, dict) else ""
    retention_policy_label = str(plan.get("retention_policy_label", "")) if isinstance(plan, dict) else ""
    entries = plan.get("immutable_storage_manifest") if isinstance(plan, dict) else None
    if not _is_sha256_hex(archive_root_hash):
        errors.append("WORM_IMMUTABLE_ARCHIVE_ROOT_HASH_MISSING")
    if not _is_sha256_hex(evidence_record_id):
        errors.append("WORM_IMMUTABLE_EVIDENCE_RECORD_CHAIN_MISSING")
    if not isinstance(entries, list) or len(entries) != len(WORM_IMMUTABLE_ARTIFACT_ORDER):
        errors.append("WORM_IMMUTABLE_MANIFEST_INVALID")
        entries = []
    if storage_mode != WORM_IMMUTABLE_STORAGE_MODE:
        errors.append("WORM_IMMUTABLE_OUTPUT_PATH_MUTABLE")
    if manifest_hash != _storage_manifest_hash(entries):
        errors.append("WORM_IMMUTABLE_MANIFEST_INVALID")
    if not _entry_order_valid(entries):
        errors.append("WORM_IMMUTABLE_ENTRY_ORDER_INVALID")
    if not _entries_valid(entries, sealed_archive_id=sealed_archive_id, archive_root_hash=archive_root_hash, archive_scope=archive_scope):
        errors.append("WORM_IMMUTABLE_OUTPUT_PATH_MUTABLE")
    if not _timestamp_is_valid(str(plan.get("created_at_utc", ""))):
        errors.append("WORM_IMMUTABLE_MANIFEST_INVALID")
    payload = _plan_payload(plan)
    if not _is_sha256_hex(plan_id) or plan_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("WORM_IMMUTABLE_MANIFEST_INVALID")
    if sealed_archive is not None:
        archive_verification = verify_sealed_audit_archive(sealed_archive)
        if not archive_verification.valid or archive_verification.archive_id != sealed_archive_id or archive_verification.archive_root_hash != archive_root_hash:
            errors.append("WORM_IMMUTABLE_ARCHIVE_ROOT_HASH_MISSING")
    if evidence_record_chain is not None:
        record_verification = verify_evidence_record(evidence_record_chain, sealed_archive=sealed_archive)
        if (
            not record_verification.valid
            or record_verification.evidence_record_id != evidence_record_id
            or record_verification.sealed_archive_id != sealed_archive_id
            or record_verification.archive_root_hash != archive_root_hash
            or plan.get("evidence_record_chain_hash") != record_verification.archive_timestamp_chain_hash
        ):
            errors.append("WORM_IMMUTABLE_EVIDENCE_RECORD_CHAIN_MISSING")
    for existing in existing_plans or []:
        if isinstance(existing, dict) and existing.get("sealed_archive_id") == sealed_archive_id:
            errors.append("WORM_IMMUTABLE_DUPLICATE_ARCHIVE_ID")
    try:
        _assert_worm_immutable_storage_safe(plan)
    except WORMImmutableStorageError:
        errors.append("WORM_IMMUTABLE_DIAGNOSTICS_UNSAFE")
    return WORMImmutableStorageVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        worm_storage_plan_id=plan_id,
        sealed_archive_id=sealed_archive_id,
        archive_root_hash=archive_root_hash,
        evidence_record_id=evidence_record_id,
        immutable_storage_manifest_hash=manifest_hash,
        storage_mode=storage_mode,
        archive_scope=archive_scope,
        retention_policy_label=retention_policy_label,
    )


def verify_worm_immutable_storage_plan_file(
    worm_immutable_storage_path: Path,
    *,
    sealed_archive_path: Path | None = None,
    evidence_record_path: Path | None = None,
    existing_plan_paths: list[Path] | None = None,
) -> WORMImmutableStorageVerificationResult:
    existing = [_load_json_object(path, "worm_immutable_storage_existing_invalid") for path in existing_plan_paths or []]
    return verify_worm_immutable_storage_plan(
        _load_json_object(worm_immutable_storage_path, "worm_immutable_storage_invalid"),
        sealed_archive=_load_json_object(sealed_archive_path, "WORM_IMMUTABLE_ARCHIVE_ROOT_HASH_MISSING") if sealed_archive_path else None,
        evidence_record_chain=_load_json_object(evidence_record_path, "WORM_IMMUTABLE_EVIDENCE_RECORD_CHAIN_MISSING") if evidence_record_path else None,
        existing_plans=existing,
    )


def explain_worm_immutable_storage_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_worm_immutable_storage_error_registry(root)
    if code not in registry:
        raise WORMImmutableStorageError("worm_immutable_storage_error_unknown:" + code)
    return {"code": code, **registry[code]}


def worm_immutable_storage_summary(plan: dict[str, Any]) -> dict[str, Any]:
    return verify_worm_immutable_storage_plan(plan).to_dict()


def redacted_worm_immutable_storage_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_worm_immutable_storage_safe(payload: Any) -> None:
    _assert_worm_immutable_storage_safe(payload)


def _storage_manifest_entries(
    *,
    sealed_archive: dict[str, Any],
    evidence_record_chain: dict[str, Any],
    sealed_archive_id: str,
    archive_root_hash: str,
    archive_scope: str,
) -> list[dict[str, Any]]:
    artifacts = {
        "sealed_audit_archive": sealed_archive,
        "evidence_record_chain": evidence_record_chain,
    }
    entries: list[dict[str, Any]] = []
    previous_binding = "0" * 64
    for position, artifact_type in enumerate(WORM_IMMUTABLE_ARTIFACT_ORDER):
        artifact_hash = _sha256_hex(_canonical_json(artifacts[artifact_type]).encode("utf-8"))
        object_id_payload = {
            "archive_root_hash": archive_root_hash,
            "artifact_hash": artifact_hash,
            "artifact_type": artifact_type,
            "sealed_archive_id": sealed_archive_id,
        }
        storage_object_id = _sha256_hex(_canonical_json(object_id_payload).encode("utf-8"))
        path = _immutable_storage_path(archive_root_hash=archive_root_hash, storage_object_id=storage_object_id)
        replay_payload = {
            "append_only_position": position,
            "archive_root_hash": archive_root_hash,
            "artifact_hash": artifact_hash,
            "artifact_type": artifact_type,
            "previous_replay_binding_hash": previous_binding,
            "sealed_archive_id": sealed_archive_id,
            "storage_object_id": storage_object_id,
            "verification_scope": archive_scope,
        }
        replay_binding_hash = _sha256_hex(_canonical_json(replay_payload).encode("utf-8"))
        entry_payload = {
            "append_only_position": position,
            "artifact_hash": artifact_hash,
            "artifact_type": artifact_type,
            "archive_root_hash": archive_root_hash,
            "replay_binding_hash": replay_binding_hash,
            "sealed_archive_id": sealed_archive_id,
            "storage_object_id": storage_object_id,
            "storage_object_path": path,
            "verification_scope": archive_scope,
        }
        entries.append({**entry_payload, "manifest_entry_hash": _sha256_hex(_canonical_json(entry_payload).encode("utf-8"))})
        previous_binding = replay_binding_hash
    return entries


def _entries_valid(entries: list[Any], *, sealed_archive_id: str, archive_root_hash: str, archive_scope: str) -> bool:
    seen_hashes: set[str] = set()
    seen_object_ids: set[str] = set()
    previous_binding = "0" * 64
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict) or entry.get("append_only_position") != position:
            return False
        artifact_type = str(entry.get("artifact_type", ""))
        artifact_hash = str(entry.get("artifact_hash", ""))
        storage_object_id = str(entry.get("storage_object_id", ""))
        if artifact_type not in WORM_IMMUTABLE_ARTIFACT_ORDER:
            return False
        if entry.get("sealed_archive_id") != sealed_archive_id or entry.get("archive_root_hash") != archive_root_hash or entry.get("verification_scope") != archive_scope:
            return False
        if not _is_sha256_hex(artifact_hash) or artifact_hash in seen_hashes:
            return False
        if not _is_sha256_hex(storage_object_id) or storage_object_id in seen_object_ids:
            return False
        expected_path = _immutable_storage_path(archive_root_hash=archive_root_hash, storage_object_id=storage_object_id)
        if entry.get("storage_object_path") != expected_path:
            return False
        replay_payload = {
            "append_only_position": position,
            "archive_root_hash": archive_root_hash,
            "artifact_hash": artifact_hash,
            "artifact_type": artifact_type,
            "previous_replay_binding_hash": previous_binding,
            "sealed_archive_id": sealed_archive_id,
            "storage_object_id": storage_object_id,
            "verification_scope": archive_scope,
        }
        replay_binding_hash = _sha256_hex(_canonical_json(replay_payload).encode("utf-8"))
        entry_payload = {
            "append_only_position": position,
            "artifact_hash": artifact_hash,
            "artifact_type": artifact_type,
            "archive_root_hash": archive_root_hash,
            "replay_binding_hash": replay_binding_hash,
            "sealed_archive_id": sealed_archive_id,
            "storage_object_id": storage_object_id,
            "storage_object_path": expected_path,
            "verification_scope": archive_scope,
        }
        if entry.get("replay_binding_hash") != replay_binding_hash:
            return False
        if entry.get("manifest_entry_hash") != _sha256_hex(_canonical_json(entry_payload).encode("utf-8")):
            return False
        seen_hashes.add(artifact_hash)
        seen_object_ids.add(storage_object_id)
        previous_binding = replay_binding_hash
    return True


def _entry_order_valid(entries: list[Any]) -> bool:
    return [entry.get("artifact_type") for entry in entries if isinstance(entry, dict)] == list(WORM_IMMUTABLE_ARTIFACT_ORDER)


def _storage_manifest_hash(entries: list[Any]) -> str:
    return _sha256_hex(_canonical_json([entry.get("manifest_entry_hash", "") for entry in entries if isinstance(entry, dict)]).encode("utf-8"))


def _plan_payload(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "archive_manifest_hash": plan.get("archive_manifest_hash", ""),
        "archive_root_hash": plan.get("archive_root_hash", ""),
        "archive_scope": plan.get("archive_scope", ""),
        "created_at_utc": plan.get("created_at_utc", ""),
        "evidence_record_chain_hash": plan.get("evidence_record_chain_hash", ""),
        "evidence_record_id": plan.get("evidence_record_id", ""),
        "governance_module_versions": plan.get("governance_module_versions", {}),
        "immutable_storage_manifest_hash": plan.get("immutable_storage_manifest_hash", ""),
        "retention_policy_label": plan.get("retention_policy_label", ""),
        "sealed_archive_id": plan.get("sealed_archive_id", ""),
        "storage_mode": plan.get("storage_mode", ""),
    }


def _immutable_storage_path(*, archive_root_hash: str, storage_object_id: str) -> str:
    return f"worm://local-only/sha256/{archive_root_hash}/{storage_object_id}"


def _assert_worm_immutable_storage_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_sealed_audit_archive_safe(redacted)
        assert_evidence_record_safe(redacted)
        if redacted != payload:
            raise WORMImmutableStorageError("WORM_IMMUTABLE_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, WORMImmutableStorageError):
            raise
        raise WORMImmutableStorageError("WORM_IMMUTABLE_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise WORMImmutableStorageError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise WORMImmutableStorageError(failure_code) from exc
    if not isinstance(payload, dict):
        raise WORMImmutableStorageError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise WORMImmutableStorageError("WORM_IMMUTABLE_MANIFEST_INVALID") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _timestamp_is_valid(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return value.endswith("Z") and parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
