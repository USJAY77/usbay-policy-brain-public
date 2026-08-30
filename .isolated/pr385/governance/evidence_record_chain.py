from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.policy_pack import redacted_policy_payload
from governance.sealed_audit_archive import (
    MODULE_VERSIONS as SEALED_AUDIT_ARCHIVE_MODULE_VERSIONS,
    assert_sealed_audit_archive_safe,
    verify_sealed_audit_archive,
)

EVIDENCE_RECORD_CHAIN_SCHEMA = "usbay.governance_evidence_record_chain.v1"
EVIDENCE_RECORD_CHAIN_ERROR_REGISTRY_PATH = Path("governance/evidence_record_chain_errors.json")
EVIDENCE_RECORD_CHAIN_ERROR_SCHEMA = "usbay.governance_evidence_record_chain_error_registry.v1"
EVIDENCE_RECORD_CHAIN_ERROR_CODES = (
    "EVIDENCE_RECORD_ARCHIVE_MISSING",
    "EVIDENCE_RECORD_CHAIN_MISMATCH",
    "EVIDENCE_RECORD_TIMESTAMP_MISSING",
    "EVIDENCE_RECORD_HASH_ALGORITHM_INVALID",
    "EVIDENCE_RECORD_RENEWAL_INVALID",
    "EVIDENCE_RECORD_APPEND_ONLY_VIOLATION",
    "EVIDENCE_RECORD_REPLAY_DETECTED",
    "EVIDENCE_RECORD_POSITION_INVALID",
    "EVIDENCE_RECORD_DIAGNOSTICS_UNSAFE",
)
GENESIS_EVIDENCE_RECORD_HASH = "0" * 64
SUPPORTED_HASH_ALGORITHMS = {"SHA256"}
MODULE_VERSIONS = {
    **SEALED_AUDIT_ARCHIVE_MODULE_VERSIONS,
    "evidence_record_chain": EVIDENCE_RECORD_CHAIN_SCHEMA,
}


class EvidenceRecordChainError(RuntimeError):
    pass


@dataclass(frozen=True)
class EvidenceRecordChainVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    evidence_record_id: str
    sealed_archive_id: str
    archive_root_hash: str
    archive_timestamp_chain_hash: str
    renewal_round: int
    append_only_position: int
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "evidence_record_id": self.evidence_record_id,
            "sealed_archive_id": self.sealed_archive_id,
            "archive_root_hash": self.archive_root_hash,
            "archive_timestamp_chain_hash": self.archive_timestamp_chain_hash,
            "renewal_round": self.renewal_round,
            "append_only_position": self.append_only_position,
            "retention_policy_label": self.retention_policy_label,
        }


def load_evidence_record_chain_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / EVIDENCE_RECORD_CHAIN_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceRecordChainError("evidence_record_chain_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != EVIDENCE_RECORD_CHAIN_ERROR_SCHEMA:
        raise EvidenceRecordChainError("evidence_record_chain_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise EvidenceRecordChainError("evidence_record_chain_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise EvidenceRecordChainError("evidence_record_chain_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(EVIDENCE_RECORD_CHAIN_ERROR_CODES) - set(registry))
    if missing:
        raise EvidenceRecordChainError("evidence_record_chain_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_evidence_record(
    sealed_archive: dict[str, Any],
    *,
    renewal_timestamp_utc: str | None = None,
    renewal_reason: str = "initial_archive_timestamp",
    hash_algorithm: str = "SHA256",
) -> dict[str, Any]:
    archive_verification = verify_sealed_audit_archive(sealed_archive)
    if not archive_verification.valid:
        raise EvidenceRecordChainError("EVIDENCE_RECORD_ARCHIVE_MISSING")
    timestamp = renewal_timestamp_utc or _utc_now()
    if not _timestamp_is_valid(timestamp):
        raise EvidenceRecordChainError("EVIDENCE_RECORD_TIMESTAMP_MISSING")
    if hash_algorithm not in SUPPORTED_HASH_ALGORITHMS:
        raise EvidenceRecordChainError("EVIDENCE_RECORD_HASH_ALGORITHM_INVALID")
    if not _reason_valid(renewal_reason):
        raise EvidenceRecordChainError("EVIDENCE_RECORD_RENEWAL_INVALID")
    return _build_chain(
        sealed_archive_id=archive_verification.archive_id,
        archive_root_hash=archive_verification.archive_root_hash,
        retention_policy_label=archive_verification.retention_policy_label,
        records=[
            _record_payload(
                sealed_archive_id=archive_verification.archive_id,
                archive_root_hash=archive_verification.archive_root_hash,
                previous_evidence_record_hash=GENESIS_EVIDENCE_RECORD_HASH,
                renewal_round=0,
                hash_algorithm=hash_algorithm,
                renewal_reason=renewal_reason,
                renewal_timestamp_utc=timestamp,
                append_only_position=0,
                retention_policy_label=archive_verification.retention_policy_label,
            )
        ],
    )


def renew_evidence_record(
    existing_chain: dict[str, Any],
    sealed_archive: dict[str, Any],
    *,
    renewal_timestamp_utc: str | None = None,
    renewal_reason: str = "scheduled_hash_renewal",
    hash_algorithm: str = "SHA256",
) -> dict[str, Any]:
    chain_verification = verify_evidence_record(existing_chain, sealed_archive=sealed_archive)
    if not chain_verification.valid:
        raise EvidenceRecordChainError("EVIDENCE_RECORD_CHAIN_MISMATCH")
    archive_verification = verify_sealed_audit_archive(sealed_archive)
    if not archive_verification.valid:
        raise EvidenceRecordChainError("EVIDENCE_RECORD_ARCHIVE_MISSING")
    if archive_verification.archive_id != chain_verification.sealed_archive_id or archive_verification.archive_root_hash != chain_verification.archive_root_hash:
        raise EvidenceRecordChainError("EVIDENCE_RECORD_ARCHIVE_MISSING")
    timestamp = renewal_timestamp_utc or _utc_now()
    if not _timestamp_is_valid(timestamp):
        raise EvidenceRecordChainError("EVIDENCE_RECORD_TIMESTAMP_MISSING")
    if hash_algorithm not in SUPPORTED_HASH_ALGORITHMS:
        raise EvidenceRecordChainError("EVIDENCE_RECORD_HASH_ALGORITHM_INVALID")
    if not _reason_valid(renewal_reason):
        raise EvidenceRecordChainError("EVIDENCE_RECORD_RENEWAL_INVALID")
    records = list(existing_chain.get("evidence_records", []))
    records.append(
        _record_payload(
            sealed_archive_id=archive_verification.archive_id,
            archive_root_hash=archive_verification.archive_root_hash,
            previous_evidence_record_hash=chain_verification.evidence_record_id,
            renewal_round=chain_verification.renewal_round + 1,
            hash_algorithm=hash_algorithm,
            renewal_reason=renewal_reason,
            renewal_timestamp_utc=timestamp,
            append_only_position=chain_verification.append_only_position + 1,
            retention_policy_label=archive_verification.retention_policy_label,
        )
    )
    return _build_chain(
        sealed_archive_id=archive_verification.archive_id,
        archive_root_hash=archive_verification.archive_root_hash,
        retention_policy_label=archive_verification.retention_policy_label,
        records=records,
    )


def create_evidence_record_file(
    sealed_archive_path: Path,
    output_path: Path,
    *,
    renewal_timestamp_utc: str | None = None,
    renewal_reason: str = "initial_archive_timestamp",
    hash_algorithm: str = "SHA256",
) -> dict[str, Any]:
    chain = create_evidence_record(
        _load_json_object(sealed_archive_path, "EVIDENCE_RECORD_ARCHIVE_MISSING"),
        renewal_timestamp_utc=renewal_timestamp_utc,
        renewal_reason=renewal_reason,
        hash_algorithm=hash_algorithm,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(chain) + "\n", encoding="utf-8")
    return chain


def renew_evidence_record_file(
    evidence_record_path: Path,
    sealed_archive_path: Path,
    output_path: Path,
    *,
    renewal_timestamp_utc: str | None = None,
    renewal_reason: str = "scheduled_hash_renewal",
    hash_algorithm: str = "SHA256",
) -> dict[str, Any]:
    chain = renew_evidence_record(
        _load_json_object(evidence_record_path, "EVIDENCE_RECORD_CHAIN_MISMATCH"),
        _load_json_object(sealed_archive_path, "EVIDENCE_RECORD_ARCHIVE_MISSING"),
        renewal_timestamp_utc=renewal_timestamp_utc,
        renewal_reason=renewal_reason,
        hash_algorithm=hash_algorithm,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(chain) + "\n", encoding="utf-8")
    return chain


def verify_evidence_record(
    chain: dict[str, Any],
    *,
    sealed_archive: dict[str, Any] | None = None,
    existing_evidence_records: list[dict[str, Any]] | None = None,
) -> EvidenceRecordChainVerificationResult:
    errors: list[str] = []
    if not isinstance(chain, dict) or chain.get("schema") != EVIDENCE_RECORD_CHAIN_SCHEMA:
        errors.append("EVIDENCE_RECORD_CHAIN_MISMATCH")
    records = chain.get("evidence_records") if isinstance(chain, dict) else None
    if not isinstance(records, list) or not records:
        errors.append("EVIDENCE_RECORD_TIMESTAMP_MISSING")
        records = []
    sealed_archive_id = str(chain.get("sealed_archive_id", "")) if isinstance(chain, dict) else ""
    archive_root_hash = str(chain.get("archive_root_hash", "")) if isinstance(chain, dict) else ""
    latest_record_id = str(chain.get("evidence_record_id", "")) if isinstance(chain, dict) else ""
    archive_timestamp_chain_hash = str(chain.get("archive_timestamp_chain_hash", "")) if isinstance(chain, dict) else ""
    retention_policy_label = str(chain.get("retention_policy_label", "")) if isinstance(chain, dict) else ""
    seen_record_ids: set[str] = set()
    seen_bindings: set[str] = set()
    expected_previous = GENESIS_EVIDENCE_RECORD_HASH
    expected_manifest_entries: list[dict[str, Any]] = []
    latest: dict[str, Any] = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append("EVIDENCE_RECORD_CHAIN_MISMATCH")
            continue
        latest = record
        if record.get("renewal_round") != index:
            errors.append("EVIDENCE_RECORD_RENEWAL_INVALID")
        if record.get("append_only_position") != index:
            errors.append("EVIDENCE_RECORD_POSITION_INVALID")
        if record.get("previous_evidence_record_hash") != expected_previous:
            errors.append("EVIDENCE_RECORD_CHAIN_MISMATCH")
        if record.get("sealed_archive_id") != sealed_archive_id or record.get("archive_root_hash") != archive_root_hash:
            errors.append("EVIDENCE_RECORD_ARCHIVE_MISSING")
        if record.get("hash_algorithm") not in SUPPORTED_HASH_ALGORITHMS:
            errors.append("EVIDENCE_RECORD_HASH_ALGORITHM_INVALID")
        if not _reason_valid(str(record.get("renewal_reason", ""))):
            errors.append("EVIDENCE_RECORD_RENEWAL_INVALID")
        if not _timestamp_is_valid(str(record.get("renewal_timestamp_utc", ""))):
            errors.append("EVIDENCE_RECORD_TIMESTAMP_MISSING")
        expected_entry = _renewal_manifest_entry(record)
        expected_manifest_entries.append(expected_entry)
        if record.get("renewal_manifest_entry") != expected_entry:
            errors.append("EVIDENCE_RECORD_APPEND_ONLY_VIOLATION")
        record_id = _record_id(record)
        if record.get("evidence_record_hash") != record_id:
            errors.append("EVIDENCE_RECORD_CHAIN_MISMATCH")
        if record_id in seen_record_ids or record.get("replay_binding_hash") in seen_bindings:
            errors.append("EVIDENCE_RECORD_REPLAY_DETECTED")
        seen_record_ids.add(record_id)
        seen_bindings.add(str(record.get("replay_binding_hash", "")))
        expected_previous = record_id
    if latest_record_id != expected_previous:
        errors.append("EVIDENCE_RECORD_CHAIN_MISMATCH")
    if chain.get("renewal_manifest") != expected_manifest_entries:
        errors.append("EVIDENCE_RECORD_APPEND_ONLY_VIOLATION")
    if archive_timestamp_chain_hash != _timestamp_chain_hash(expected_manifest_entries):
        errors.append("EVIDENCE_RECORD_CHAIN_MISMATCH")
    if latest:
        expected_top = _top_level_from_records(
            sealed_archive_id=sealed_archive_id,
            archive_root_hash=archive_root_hash,
            retention_policy_label=retention_policy_label,
            records=records,
            manifest_entries=expected_manifest_entries,
        )
        for key, expected_value in expected_top.items():
            if chain.get(key) != expected_value:
                errors.append("EVIDENCE_RECORD_CHAIN_MISMATCH")
                break
    if sealed_archive is not None:
        archive_verification = verify_sealed_audit_archive(sealed_archive)
        if not archive_verification.valid:
            errors.append("EVIDENCE_RECORD_ARCHIVE_MISSING")
        elif (
            archive_verification.archive_id != sealed_archive_id
            or archive_verification.archive_root_hash != archive_root_hash
            or archive_verification.retention_policy_label != retention_policy_label
        ):
            errors.append("EVIDENCE_RECORD_ARCHIVE_MISSING")
    for existing in existing_evidence_records or []:
        if isinstance(existing, dict) and existing.get("evidence_record_id") == latest_record_id:
            errors.append("EVIDENCE_RECORD_REPLAY_DETECTED")
    try:
        _assert_evidence_record_safe(chain)
    except EvidenceRecordChainError:
        errors.append("EVIDENCE_RECORD_DIAGNOSTICS_UNSAFE")
    return EvidenceRecordChainVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        evidence_record_id=latest_record_id,
        sealed_archive_id=sealed_archive_id,
        archive_root_hash=archive_root_hash,
        archive_timestamp_chain_hash=archive_timestamp_chain_hash,
        renewal_round=int(latest.get("renewal_round", -1)) if latest else -1,
        append_only_position=int(latest.get("append_only_position", -1)) if latest else -1,
        retention_policy_label=retention_policy_label,
    )


def verify_evidence_record_file(
    evidence_record_path: Path,
    *,
    sealed_archive_path: Path | None = None,
    existing_evidence_record_paths: list[Path] | None = None,
) -> EvidenceRecordChainVerificationResult:
    existing = [_load_json_object(path, "evidence_record_existing_invalid") for path in existing_evidence_record_paths or []]
    return verify_evidence_record(
        _load_json_object(evidence_record_path, "evidence_record_invalid"),
        sealed_archive=_load_json_object(sealed_archive_path, "EVIDENCE_RECORD_ARCHIVE_MISSING") if sealed_archive_path else None,
        existing_evidence_records=existing,
    )


def explain_evidence_record_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_evidence_record_chain_error_registry(root)
    if code not in registry:
        raise EvidenceRecordChainError("evidence_record_error_unknown:" + code)
    return {"code": code, **registry[code]}


def evidence_record_summary(chain: dict[str, Any]) -> dict[str, Any]:
    return verify_evidence_record(chain).to_dict()


def redacted_evidence_record_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_evidence_record_safe(payload: Any) -> None:
    _assert_evidence_record_safe(payload)


def _build_chain(
    *,
    sealed_archive_id: str,
    archive_root_hash: str,
    retention_policy_label: str,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    finalized_records: list[dict[str, Any]] = []
    for record in records:
        finalized = dict(record)
        finalized["renewal_manifest_entry"] = _renewal_manifest_entry(finalized)
        finalized["evidence_record_hash"] = _record_id(finalized)
        finalized_records.append(finalized)
    manifest_entries = [record["renewal_manifest_entry"] for record in finalized_records]
    top = _top_level_from_records(
        sealed_archive_id=sealed_archive_id,
        archive_root_hash=archive_root_hash,
        retention_policy_label=retention_policy_label,
        records=finalized_records,
        manifest_entries=manifest_entries,
    )
    chain = {
        "schema": EVIDENCE_RECORD_CHAIN_SCHEMA,
        "evidence_records": finalized_records,
        "renewal_manifest": manifest_entries,
        **top,
    }
    _assert_evidence_record_safe(chain)
    return chain


def _record_payload(
    *,
    sealed_archive_id: str,
    archive_root_hash: str,
    previous_evidence_record_hash: str,
    renewal_round: int,
    hash_algorithm: str,
    renewal_reason: str,
    renewal_timestamp_utc: str,
    append_only_position: int,
    retention_policy_label: str,
) -> dict[str, Any]:
    timestamp_continuity_hash = _timestamp_continuity_hash(
        sealed_archive_id=sealed_archive_id,
        archive_root_hash=archive_root_hash,
        previous_evidence_record_hash=previous_evidence_record_hash,
        renewal_round=renewal_round,
        renewal_timestamp_utc=renewal_timestamp_utc,
    )
    replay_binding_hash = _replay_binding_hash(
        sealed_archive_id=sealed_archive_id,
        archive_root_hash=archive_root_hash,
        previous_evidence_record_hash=previous_evidence_record_hash,
        timestamp_continuity_hash=timestamp_continuity_hash,
        append_only_position=append_only_position,
    )
    return {
        "append_only_position": append_only_position,
        "archive_root_hash": archive_root_hash,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "hash_algorithm": hash_algorithm,
        "previous_evidence_record_hash": previous_evidence_record_hash,
        "renewal_reason": renewal_reason,
        "renewal_round": renewal_round,
        "renewal_timestamp_utc": renewal_timestamp_utc,
        "replay_binding_hash": replay_binding_hash,
        "retention_policy_label": retention_policy_label,
        "sealed_archive_id": sealed_archive_id,
        "timestamp_continuity_hash": timestamp_continuity_hash,
    }


def _renewal_manifest_entry(record: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "append_only_position": record.get("append_only_position", -1),
        "prior_chain_hash": record.get("previous_evidence_record_hash", ""),
        "renewed_archive_root_hash": record.get("archive_root_hash", ""),
        "replay_binding_hash": record.get("replay_binding_hash", ""),
        "timestamp_continuity_hash": record.get("timestamp_continuity_hash", ""),
    }
    return {
        **payload,
        "renewal_entry_hash": _sha256_hex(_canonical_json(payload).encode("utf-8")),
    }


def _top_level_from_records(
    *,
    sealed_archive_id: str,
    archive_root_hash: str,
    retention_policy_label: str,
    records: list[dict[str, Any]],
    manifest_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    latest = records[-1]
    chain_hash = _timestamp_chain_hash(manifest_entries)
    return {
        "append_only_position": latest.get("append_only_position", -1),
        "archive_root_hash": archive_root_hash,
        "archive_timestamp_chain_hash": chain_hash,
        "evidence_record_id": latest.get("evidence_record_hash", ""),
        "governance_module_versions": dict(MODULE_VERSIONS),
        "hash_algorithm": latest.get("hash_algorithm", ""),
        "previous_evidence_record_hash": latest.get("previous_evidence_record_hash", ""),
        "renewal_reason": latest.get("renewal_reason", ""),
        "renewal_round": latest.get("renewal_round", -1),
        "renewal_timestamp_utc": latest.get("renewal_timestamp_utc", ""),
        "replay_binding_hash": latest.get("replay_binding_hash", ""),
        "retention_policy_label": retention_policy_label,
        "sealed_archive_id": sealed_archive_id,
    }


def _record_id(record: dict[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "evidence_record_hash"}
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def _timestamp_chain_hash(manifest_entries: list[dict[str, Any]]) -> str:
    return _sha256_hex(_canonical_json([entry.get("renewal_entry_hash", "") for entry in manifest_entries]).encode("utf-8"))


def _timestamp_continuity_hash(
    *,
    sealed_archive_id: str,
    archive_root_hash: str,
    previous_evidence_record_hash: str,
    renewal_round: int,
    renewal_timestamp_utc: str,
) -> str:
    payload = {
        "archive_root_hash": archive_root_hash,
        "previous_evidence_record_hash": previous_evidence_record_hash,
        "renewal_round": renewal_round,
        "renewal_timestamp_utc": renewal_timestamp_utc,
        "sealed_archive_id": sealed_archive_id,
    }
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def _replay_binding_hash(
    *,
    sealed_archive_id: str,
    archive_root_hash: str,
    previous_evidence_record_hash: str,
    timestamp_continuity_hash: str,
    append_only_position: int,
) -> str:
    payload = {
        "append_only_position": append_only_position,
        "archive_root_hash": archive_root_hash,
        "previous_evidence_record_hash": previous_evidence_record_hash,
        "sealed_archive_id": sealed_archive_id,
        "timestamp_continuity_hash": timestamp_continuity_hash,
    }
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def _reason_valid(value: str) -> bool:
    return bool(value) and all(part.replace("-", "").replace("_", "").isalnum() for part in value.split(".")) and len(value) <= 128


def _assert_evidence_record_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_sealed_audit_archive_safe(redacted)
        if redacted != payload:
            raise EvidenceRecordChainError("EVIDENCE_RECORD_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, EvidenceRecordChainError):
            raise
        raise EvidenceRecordChainError("EVIDENCE_RECORD_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise EvidenceRecordChainError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvidenceRecordChainError(failure_code) from exc
    if not isinstance(payload, dict):
        raise EvidenceRecordChainError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise EvidenceRecordChainError("EVIDENCE_RECORD_CHAIN_MISMATCH") from exc


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
