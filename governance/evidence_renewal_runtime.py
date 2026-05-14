from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.evidence_record_chain import assert_evidence_record_safe, verify_evidence_record
from governance.policy_pack import redacted_policy_payload
from governance.regulator_export_profile import (
    MODULE_VERSIONS as REGULATOR_EXPORT_MODULE_VERSIONS,
    assert_regulator_export_profile_safe,
    verify_regulator_export_profile,
)
from governance.sealed_audit_archive import assert_sealed_audit_archive_safe, verify_sealed_audit_archive
from governance.tsa_live_verification import assert_tsa_live_verification_safe, verify_tsa_live_verification_plan
from governance.worm_immutable_storage import assert_worm_immutable_storage_safe, verify_worm_immutable_storage_plan

EVIDENCE_RENEWAL_RUNTIME_SCHEMA = "usbay.governance_evidence_renewal_runtime.v1"
EVIDENCE_RENEWAL_RUNTIME_ERROR_REGISTRY_PATH = Path("governance/evidence_renewal_runtime_errors.json")
EVIDENCE_RENEWAL_RUNTIME_ERROR_SCHEMA = "usbay.governance_evidence_renewal_runtime_error_registry.v1"
EVIDENCE_RENEWAL_RUNTIME_ERROR_CODES = (
    "EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING",
    "EVIDENCE_RENEWAL_RUNTIME_SEALED_ARCHIVE_MISSING",
    "EVIDENCE_RENEWAL_RUNTIME_WORM_MANIFEST_MISSING",
    "EVIDENCE_RENEWAL_RUNTIME_TSA_METADATA_MISSING",
    "EVIDENCE_RENEWAL_RUNTIME_REGULATOR_PROFILE_MISSING",
    "EVIDENCE_RENEWAL_RUNTIME_ENTRY_ORDER_INVALID",
    "EVIDENCE_RENEWAL_RUNTIME_DUPLICATE_RENEWAL_ID",
    "EVIDENCE_RENEWAL_RUNTIME_POLICY_DECISION_STALE",
    "EVIDENCE_RENEWAL_RUNTIME_PATH_MUTABLE",
    "EVIDENCE_RENEWAL_RUNTIME_RAW_PAYLOAD_LEAKAGE",
    "EVIDENCE_RENEWAL_RUNTIME_DIAGNOSTICS_UNSAFE",
)
EVIDENCE_RENEWAL_RUNTIME_MODE = "LOCAL_ONLY"
DEFAULT_POLICY_DECISION_MAX_AGE_SECONDS = 86_400
MODULE_VERSIONS = {
    **REGULATOR_EXPORT_MODULE_VERSIONS,
    "evidence_renewal_runtime": EVIDENCE_RENEWAL_RUNTIME_SCHEMA,
}


class EvidenceRenewalRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class EvidenceRenewalRuntimeVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    evidence_renewal_runtime_id: str
    evidence_record_id: str
    sealed_archive_id: str
    sealed_archive_root_hash: str
    worm_manifest_hash: str
    tsa_timestamp_token_hash: str
    regulator_export_profile_hash: str
    policy_decision_hash: str
    latest_renewal_runtime_hash: str
    append_only_position: int
    runtime_mode: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "evidence_renewal_runtime_id": self.evidence_renewal_runtime_id,
            "evidence_record_id": self.evidence_record_id,
            "sealed_archive_id": self.sealed_archive_id,
            "sealed_archive_root_hash": self.sealed_archive_root_hash,
            "worm_manifest_hash": self.worm_manifest_hash,
            "tsa_timestamp_token_hash": self.tsa_timestamp_token_hash,
            "regulator_export_profile_hash": self.regulator_export_profile_hash,
            "policy_decision_hash": self.policy_decision_hash,
            "latest_renewal_runtime_hash": self.latest_renewal_runtime_hash,
            "append_only_position": self.append_only_position,
            "runtime_mode": self.runtime_mode,
            "retention_policy_label": self.retention_policy_label,
        }


def load_evidence_renewal_runtime_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / EVIDENCE_RENEWAL_RUNTIME_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceRenewalRuntimeError("evidence_renewal_runtime_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != EVIDENCE_RENEWAL_RUNTIME_ERROR_SCHEMA:
        raise EvidenceRenewalRuntimeError("evidence_renewal_runtime_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise EvidenceRenewalRuntimeError("evidence_renewal_runtime_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise EvidenceRenewalRuntimeError("evidence_renewal_runtime_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(EVIDENCE_RENEWAL_RUNTIME_ERROR_CODES) - set(registry))
    if missing:
        raise EvidenceRenewalRuntimeError("evidence_renewal_runtime_error_registry_incomplete:" + ",".join(missing))
    return registry


def prepare_evidence_renewal_runtime_record(
    *,
    evidence_record_chain: dict[str, Any],
    sealed_archive: dict[str, Any],
    worm_immutable_storage: dict[str, Any],
    tsa_live_verification: dict[str, Any],
    regulator_export_profile: dict[str, Any],
    policy_decision_metadata: dict[str, Any],
    created_at_utc: str | None = None,
    policy_decision_max_age_seconds: int = DEFAULT_POLICY_DECISION_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    archive_result = verify_sealed_audit_archive(sealed_archive)
    if not archive_result.valid:
        raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_SEALED_ARCHIVE_MISSING")
    record_result = verify_evidence_record(evidence_record_chain, sealed_archive=sealed_archive)
    if not record_result.valid:
        raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING")
    worm_result = verify_worm_immutable_storage_plan(
        worm_immutable_storage,
        sealed_archive=sealed_archive,
        evidence_record_chain=evidence_record_chain,
    )
    if not worm_result.valid:
        raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_WORM_MANIFEST_MISSING")
    tsa_result = verify_tsa_live_verification_plan(tsa_live_verification)
    if not tsa_result.valid:
        raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_TSA_METADATA_MISSING")
    regulator_result = verify_regulator_export_profile(
        regulator_export_profile,
        sealed_archive=sealed_archive,
        evidence_record_chain=evidence_record_chain,
        worm_immutable_storage=worm_immutable_storage,
        tsa_live_verification=tsa_live_verification,
        policy_decision_metadata=policy_decision_metadata,
    )
    if not regulator_result.valid:
        raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_REGULATOR_PROFILE_MISSING")
    created_at = created_at_utc or _utc_now()
    if not _timestamp_is_valid(created_at):
        raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_POLICY_DECISION_STALE")
    if not _policy_decision_fresh(policy_decision_metadata, created_at, policy_decision_max_age_seconds):
        raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_POLICY_DECISION_STALE")
    bindings = _runtime_bindings(
        record_result=record_result,
        archive_result=archive_result,
        worm_result=worm_result,
        tsa_result=tsa_result,
        regulator_result=regulator_result,
        policy_decision_metadata=policy_decision_metadata,
    )
    entry = _runtime_entry(
        bindings=bindings,
        append_only_position=0,
        previous_renewal_runtime_hash="0" * 64,
        created_at_utc=created_at,
    )
    manifest_hash = _manifest_hash([entry])
    payload = {
        **bindings,
        "created_at_utc": created_at,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "latest_renewal_runtime_hash": entry["renewal_runtime_hash"],
        "policy_decision_max_age_seconds": int(policy_decision_max_age_seconds),
        "renewal_runtime_manifest_hash": manifest_hash,
        "retention_policy_label": archive_result.retention_policy_label,
        "runtime_mode": EVIDENCE_RENEWAL_RUNTIME_MODE,
        "runtime_output_path": _runtime_output_path(entry["renewal_runtime_hash"]),
    }
    record = {
        "schema": EVIDENCE_RENEWAL_RUNTIME_SCHEMA,
        "evidence_renewal_runtime_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        "renewal_runtime_entries": [entry],
        **payload,
    }
    _assert_evidence_renewal_runtime_safe(record)
    return record


def prepare_evidence_renewal_runtime_record_file(
    *,
    evidence_record_path: Path,
    sealed_archive_path: Path,
    worm_immutable_storage_path: Path,
    tsa_live_verification_path: Path,
    regulator_export_profile_path: Path,
    policy_decision_metadata_path: Path,
    output_path: Path,
    created_at_utc: str | None = None,
    policy_decision_max_age_seconds: int = DEFAULT_POLICY_DECISION_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    record = prepare_evidence_renewal_runtime_record(
        evidence_record_chain=_load_json_object(evidence_record_path, "EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING"),
        sealed_archive=_load_json_object(sealed_archive_path, "EVIDENCE_RENEWAL_RUNTIME_SEALED_ARCHIVE_MISSING"),
        worm_immutable_storage=_load_json_object(worm_immutable_storage_path, "EVIDENCE_RENEWAL_RUNTIME_WORM_MANIFEST_MISSING"),
        tsa_live_verification=_load_json_object(tsa_live_verification_path, "EVIDENCE_RENEWAL_RUNTIME_TSA_METADATA_MISSING"),
        regulator_export_profile=_load_json_object(regulator_export_profile_path, "EVIDENCE_RENEWAL_RUNTIME_REGULATOR_PROFILE_MISSING"),
        policy_decision_metadata=_load_json_object(policy_decision_metadata_path, "EVIDENCE_RENEWAL_RUNTIME_POLICY_DECISION_STALE"),
        created_at_utc=created_at_utc,
        policy_decision_max_age_seconds=policy_decision_max_age_seconds,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(record) + "\n", encoding="utf-8")
    return record


def verify_evidence_renewal_runtime_record(
    record: dict[str, Any],
    *,
    evidence_record_chain: dict[str, Any] | None = None,
    sealed_archive: dict[str, Any] | None = None,
    worm_immutable_storage: dict[str, Any] | None = None,
    tsa_live_verification: dict[str, Any] | None = None,
    regulator_export_profile: dict[str, Any] | None = None,
    policy_decision_metadata: dict[str, Any] | None = None,
    existing_records: list[dict[str, Any]] | None = None,
) -> EvidenceRenewalRuntimeVerificationResult:
    errors: list[str] = []
    if not isinstance(record, dict) or record.get("schema") != EVIDENCE_RENEWAL_RUNTIME_SCHEMA:
        errors.append("EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING")
    runtime_id = str(record.get("evidence_renewal_runtime_id", "")) if isinstance(record, dict) else ""
    evidence_record_id = str(record.get("evidence_record_id", "")) if isinstance(record, dict) else ""
    sealed_archive_id = str(record.get("sealed_archive_id", "")) if isinstance(record, dict) else ""
    archive_root_hash = str(record.get("sealed_archive_root_hash", "")) if isinstance(record, dict) else ""
    worm_manifest_hash = str(record.get("worm_manifest_hash", "")) if isinstance(record, dict) else ""
    tsa_token_hash = str(record.get("tsa_timestamp_token_hash", "")) if isinstance(record, dict) else ""
    regulator_hash = str(record.get("regulator_export_profile_hash", "")) if isinstance(record, dict) else ""
    policy_hash = str(record.get("policy_decision_hash", "")) if isinstance(record, dict) else ""
    latest_hash = str(record.get("latest_renewal_runtime_hash", "")) if isinstance(record, dict) else ""
    runtime_mode = str(record.get("runtime_mode", "")) if isinstance(record, dict) else ""
    retention = str(record.get("retention_policy_label", "")) if isinstance(record, dict) else ""
    entries = record.get("renewal_runtime_entries") if isinstance(record, dict) else None
    created_at = str(record.get("created_at_utc", "")) if isinstance(record, dict) else ""
    max_age = record.get("policy_decision_max_age_seconds") if isinstance(record, dict) else None
    if not _is_sha256_hex(evidence_record_id):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING")
    if not _is_sha256_hex(sealed_archive_id) or not _is_sha256_hex(archive_root_hash):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_SEALED_ARCHIVE_MISSING")
    if not _is_sha256_hex(worm_manifest_hash):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_WORM_MANIFEST_MISSING")
    if not _is_sha256_hex(tsa_token_hash):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_TSA_METADATA_MISSING")
    if not _is_sha256_hex(regulator_hash):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_REGULATOR_PROFILE_MISSING")
    if not _is_sha256_hex(policy_hash):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_POLICY_DECISION_STALE")
    if runtime_mode != EVIDENCE_RENEWAL_RUNTIME_MODE or record.get("runtime_output_path") != _runtime_output_path(latest_hash):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_PATH_MUTABLE")
    if not isinstance(max_age, int) or max_age <= 0 or not _timestamp_is_valid(created_at):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_POLICY_DECISION_STALE")
    if policy_decision_metadata is not None:
        if _hash_object(policy_decision_metadata) != policy_hash or not _policy_decision_fresh(policy_decision_metadata, created_at, int(max_age) if isinstance(max_age, int) else 0):
            errors.append("EVIDENCE_RENEWAL_RUNTIME_POLICY_DECISION_STALE")
    if not isinstance(entries, list) or not entries:
        errors.append("EVIDENCE_RENEWAL_RUNTIME_ENTRY_ORDER_INVALID")
        entries = []
    if _manifest_hash(entries) != record.get("renewal_runtime_manifest_hash"):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_ENTRY_ORDER_INVALID")
    if not _entries_valid(entries, _record_bindings(record)):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_ENTRY_ORDER_INVALID")
    if entries and isinstance(entries[-1], dict) and latest_hash != str(entries[-1].get("renewal_runtime_hash", "")):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_ENTRY_ORDER_INVALID")
    payload = _record_payload(record)
    if not _is_sha256_hex(runtime_id) or runtime_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("EVIDENCE_RENEWAL_RUNTIME_ENTRY_ORDER_INVALID")
    if sealed_archive is not None:
        archive_result = verify_sealed_audit_archive(sealed_archive)
        if not archive_result.valid or archive_result.archive_id != sealed_archive_id or archive_result.archive_root_hash != archive_root_hash:
            errors.append("EVIDENCE_RENEWAL_RUNTIME_SEALED_ARCHIVE_MISSING")
    if evidence_record_chain is not None:
        record_result = verify_evidence_record(evidence_record_chain, sealed_archive=sealed_archive)
        if not record_result.valid or record_result.evidence_record_id != evidence_record_id or record_result.archive_root_hash != archive_root_hash:
            errors.append("EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING")
    if worm_immutable_storage is not None:
        worm_result = verify_worm_immutable_storage_plan(worm_immutable_storage, sealed_archive=sealed_archive, evidence_record_chain=evidence_record_chain)
        if not worm_result.valid or worm_result.immutable_storage_manifest_hash != worm_manifest_hash:
            errors.append("EVIDENCE_RENEWAL_RUNTIME_WORM_MANIFEST_MISSING")
    if tsa_live_verification is not None:
        tsa_result = verify_tsa_live_verification_plan(tsa_live_verification)
        if not tsa_result.valid or tsa_result.timestamp_token_hash != tsa_token_hash:
            errors.append("EVIDENCE_RENEWAL_RUNTIME_TSA_METADATA_MISSING")
    if regulator_export_profile is not None:
        regulator_result = verify_regulator_export_profile(
            regulator_export_profile,
            sealed_archive=sealed_archive,
            evidence_record_chain=evidence_record_chain,
            worm_immutable_storage=worm_immutable_storage,
            tsa_live_verification=tsa_live_verification,
            policy_decision_metadata=policy_decision_metadata,
        )
        if not regulator_result.valid or regulator_result.export_profile_hash != regulator_hash:
            errors.append("EVIDENCE_RENEWAL_RUNTIME_REGULATOR_PROFILE_MISSING")
    for existing in existing_records or []:
        if isinstance(existing, dict) and existing.get("evidence_renewal_runtime_id") == runtime_id:
            errors.append("EVIDENCE_RENEWAL_RUNTIME_DUPLICATE_RENEWAL_ID")
    try:
        _assert_evidence_renewal_runtime_safe(record)
    except EvidenceRenewalRuntimeError as exc:
        if str(exc) == "EVIDENCE_RENEWAL_RUNTIME_RAW_PAYLOAD_LEAKAGE":
            errors.append("EVIDENCE_RENEWAL_RUNTIME_RAW_PAYLOAD_LEAKAGE")
        else:
            errors.append("EVIDENCE_RENEWAL_RUNTIME_DIAGNOSTICS_UNSAFE")
    return EvidenceRenewalRuntimeVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        evidence_renewal_runtime_id=runtime_id,
        evidence_record_id=evidence_record_id,
        sealed_archive_id=sealed_archive_id,
        sealed_archive_root_hash=archive_root_hash,
        worm_manifest_hash=worm_manifest_hash,
        tsa_timestamp_token_hash=tsa_token_hash,
        regulator_export_profile_hash=regulator_hash,
        policy_decision_hash=policy_hash,
        latest_renewal_runtime_hash=latest_hash,
        append_only_position=int(entries[-1].get("append_only_position", -1)) if entries and isinstance(entries[-1], dict) else -1,
        runtime_mode=runtime_mode,
        retention_policy_label=retention,
    )


def verify_evidence_renewal_runtime_record_file(
    evidence_renewal_runtime_path: Path,
    *,
    evidence_record_path: Path | None = None,
    sealed_archive_path: Path | None = None,
    worm_immutable_storage_path: Path | None = None,
    tsa_live_verification_path: Path | None = None,
    regulator_export_profile_path: Path | None = None,
    policy_decision_metadata_path: Path | None = None,
) -> EvidenceRenewalRuntimeVerificationResult:
    return verify_evidence_renewal_runtime_record(
        _load_json_object(evidence_renewal_runtime_path, "evidence_renewal_runtime_invalid"),
        evidence_record_chain=_load_json_object(evidence_record_path, "EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING") if evidence_record_path else None,
        sealed_archive=_load_json_object(sealed_archive_path, "EVIDENCE_RENEWAL_RUNTIME_SEALED_ARCHIVE_MISSING") if sealed_archive_path else None,
        worm_immutable_storage=_load_json_object(worm_immutable_storage_path, "EVIDENCE_RENEWAL_RUNTIME_WORM_MANIFEST_MISSING") if worm_immutable_storage_path else None,
        tsa_live_verification=_load_json_object(tsa_live_verification_path, "EVIDENCE_RENEWAL_RUNTIME_TSA_METADATA_MISSING") if tsa_live_verification_path else None,
        regulator_export_profile=_load_json_object(regulator_export_profile_path, "EVIDENCE_RENEWAL_RUNTIME_REGULATOR_PROFILE_MISSING") if regulator_export_profile_path else None,
        policy_decision_metadata=_load_json_object(policy_decision_metadata_path, "EVIDENCE_RENEWAL_RUNTIME_POLICY_DECISION_STALE") if policy_decision_metadata_path else None,
    )


def explain_evidence_renewal_runtime_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_evidence_renewal_runtime_error_registry(root)
    if code not in registry:
        raise EvidenceRenewalRuntimeError("evidence_renewal_runtime_error_unknown:" + code)
    return {"code": code, **registry[code]}


def evidence_renewal_runtime_summary(record: dict[str, Any]) -> dict[str, Any]:
    return verify_evidence_renewal_runtime_record(record).to_dict()


def redacted_evidence_renewal_runtime_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_evidence_renewal_runtime_safe(payload: Any) -> None:
    _assert_evidence_renewal_runtime_safe(payload)


def _runtime_bindings(
    *,
    record_result: Any,
    archive_result: Any,
    worm_result: Any,
    tsa_result: Any,
    regulator_result: Any,
    policy_decision_metadata: dict[str, Any],
) -> dict[str, str]:
    return {
        "evidence_record_id": record_result.evidence_record_id,
        "sealed_archive_id": archive_result.archive_id,
        "sealed_archive_root_hash": archive_result.archive_root_hash,
        "worm_manifest_hash": worm_result.immutable_storage_manifest_hash,
        "tsa_timestamp_token_hash": tsa_result.timestamp_token_hash,
        "regulator_export_profile_hash": regulator_result.export_profile_hash,
        "policy_decision_hash": _hash_object(policy_decision_metadata),
    }


def _runtime_entry(*, bindings: dict[str, str], append_only_position: int, previous_renewal_runtime_hash: str, created_at_utc: str) -> dict[str, Any]:
    replay_binding_payload = {
        **bindings,
        "append_only_position": append_only_position,
        "created_at_utc": created_at_utc,
        "previous_renewal_runtime_hash": previous_renewal_runtime_hash,
        "runtime_mode": EVIDENCE_RENEWAL_RUNTIME_MODE,
    }
    replay_binding_hash = _sha256_hex(_canonical_json(replay_binding_payload).encode("utf-8"))
    entry_payload = {
        **bindings,
        "append_only_position": append_only_position,
        "created_at_utc": created_at_utc,
        "previous_renewal_runtime_hash": previous_renewal_runtime_hash,
        "replay_binding_hash": replay_binding_hash,
        "runtime_mode": EVIDENCE_RENEWAL_RUNTIME_MODE,
    }
    return {**entry_payload, "renewal_runtime_hash": _sha256_hex(_canonical_json(entry_payload).encode("utf-8"))}


def _entries_valid(entries: list[Any], bindings: dict[str, str]) -> bool:
    previous = "0" * 64
    seen_hashes: set[str] = set()
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict) or entry.get("append_only_position") != position:
            return False
        if entry.get("previous_renewal_runtime_hash") != previous:
            return False
        if any(entry.get(key) != value for key, value in bindings.items()):
            return False
        if entry.get("runtime_mode") != EVIDENCE_RENEWAL_RUNTIME_MODE or not _timestamp_is_valid(str(entry.get("created_at_utc", ""))):
            return False
        expected = _runtime_entry(
            bindings=bindings,
            append_only_position=position,
            previous_renewal_runtime_hash=previous,
            created_at_utc=str(entry.get("created_at_utc", "")),
        )
        if entry != expected:
            return False
        renewal_hash = str(entry.get("renewal_runtime_hash", ""))
        if renewal_hash in seen_hashes:
            return False
        seen_hashes.add(renewal_hash)
        previous = renewal_hash
    return True


def _record_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        **_record_bindings(record),
        "created_at_utc": record.get("created_at_utc", ""),
        "governance_module_versions": record.get("governance_module_versions", {}),
        "latest_renewal_runtime_hash": record.get("latest_renewal_runtime_hash", ""),
        "policy_decision_max_age_seconds": record.get("policy_decision_max_age_seconds", ""),
        "renewal_runtime_manifest_hash": record.get("renewal_runtime_manifest_hash", ""),
        "retention_policy_label": record.get("retention_policy_label", ""),
        "runtime_mode": record.get("runtime_mode", ""),
        "runtime_output_path": record.get("runtime_output_path", ""),
    }


def _record_bindings(record: dict[str, Any]) -> dict[str, str]:
    return {
        "evidence_record_id": str(record.get("evidence_record_id", "")),
        "sealed_archive_id": str(record.get("sealed_archive_id", "")),
        "sealed_archive_root_hash": str(record.get("sealed_archive_root_hash", "")),
        "worm_manifest_hash": str(record.get("worm_manifest_hash", "")),
        "tsa_timestamp_token_hash": str(record.get("tsa_timestamp_token_hash", "")),
        "regulator_export_profile_hash": str(record.get("regulator_export_profile_hash", "")),
        "policy_decision_hash": str(record.get("policy_decision_hash", "")),
    }


def _manifest_hash(entries: list[Any]) -> str:
    return _sha256_hex(_canonical_json([entry.get("renewal_runtime_hash", "") for entry in entries if isinstance(entry, dict)]).encode("utf-8"))


def _runtime_output_path(latest_hash: str) -> str:
    return f"evidence-renewal-runtime://local-only/sha256/{latest_hash}"


def _policy_decision_fresh(metadata: dict[str, Any], checked_at: str, max_age_seconds: int) -> bool:
    if not isinstance(metadata, dict) or max_age_seconds <= 0:
        return False
    required = {"policy_decision_id", "policy_decision", "policy_hash", "decision_timestamp_utc", "actor_hash", "policy_version_hash"}
    if set(metadata) != required:
        return False
    if str(metadata.get("policy_decision", "")) not in {"ALLOW", "DENY", "REQUIRE_HUMAN_REVIEW", "FAIL_CLOSED"}:
        return False
    if any(not _is_sha256_hex(str(metadata.get(key, ""))) for key in ("policy_decision_id", "policy_hash", "actor_hash", "policy_version_hash")):
        return False
    decision_time = str(metadata.get("decision_timestamp_utc", ""))
    if not _timestamp_is_valid(decision_time) or not _timestamp_is_valid(checked_at):
        return False
    decision_dt = datetime.fromisoformat(decision_time.replace("Z", "+00:00"))
    checked_dt = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    age = (checked_dt - decision_dt).total_seconds()
    return 0 <= age <= max_age_seconds


def _assert_evidence_renewal_runtime_safe(payload: Any) -> None:
    try:
        if _contains_raw_payload_marker(payload):
            raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_RAW_PAYLOAD_LEAKAGE")
        redacted = redacted_policy_payload(payload)
        assert_evidence_record_safe(redacted)
        assert_sealed_audit_archive_safe(redacted)
        assert_worm_immutable_storage_safe(redacted)
        assert_tsa_live_verification_safe(redacted)
        assert_regulator_export_profile_safe(redacted)
        if redacted != payload:
            raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, EvidenceRenewalRuntimeError):
            raise
        raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_DIAGNOSTICS_UNSAFE") from exc


def _contains_raw_payload_marker(payload: Any) -> bool:
    text = _canonical_json(payload).lower()
    markers = (
        "raw_payload",
        "raw_governance_payload",
        "raw_ocsp",
        "raw_crl",
        "ocsp_bytes",
        "crl_bytes",
        "runtime_artifact",
        "raw_runtime_renewal",
    )
    return any(marker in text for marker in markers)


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise EvidenceRenewalRuntimeError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceRenewalRuntimeError(failure_code) from exc
    if not isinstance(payload, dict):
        raise EvidenceRenewalRuntimeError(failure_code)
    return payload


def _hash_object(payload: Any) -> str:
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise EvidenceRenewalRuntimeError("EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING") from exc


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


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
