from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.audit_evidence import (
    AUDIT_PIPELINE_STAGE_SEQUENCE,
    AuditPipelineSummary,
    canonical_audit_json,
    serialize_audit_pipeline_summary,
    sha256_audit_hash,
)


AUDIT_PIPELINE_PERSISTENCE_SCHEMA = "usbay.governance.audit_pipeline_persistence.v1"
AUDIT_PIPELINE_PERSISTENCE_RECORD_SCHEMA = AUDIT_PIPELINE_PERSISTENCE_SCHEMA + ".record"
AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH = "sha256:" + ("0" * 64)
AUDIT_PIPELINE_PERSISTENCE_STATUSES = (
    "PERSISTED",
    "ALREADY_PERSISTED",
    "BLOCKED",
)
AUDIT_PIPELINE_PERSISTENCE_ERRORS = (
    "AUDIT_PIPELINE_PERSISTENCE_PATH_INVALID",
    "AUDIT_PIPELINE_PERSISTENCE_LOCKED",
    "AUDIT_PIPELINE_PERSISTENCE_READ_FAILED",
    "AUDIT_PIPELINE_PERSISTENCE_WRITE_FAILED",
    "AUDIT_PIPELINE_PERSISTENCE_RECORD_MALFORMED",
    "AUDIT_PIPELINE_PERSISTENCE_SCHEMA_INVALID",
    "AUDIT_PIPELINE_PERSISTENCE_SUMMARY_INVALID",
    "AUDIT_PIPELINE_PERSISTENCE_CONTEXT_MISSING",
    "AUDIT_PIPELINE_PERSISTENCE_PREVIOUS_HASH_MISSING",
    "AUDIT_PIPELINE_PERSISTENCE_PREVIOUS_HASH_MISMATCH",
    "AUDIT_PIPELINE_PERSISTENCE_POSITION_INVALID",
    "AUDIT_PIPELINE_PERSISTENCE_HASH_INVALID",
    "AUDIT_PIPELINE_PERSISTENCE_RECORD_HASH_MISMATCH",
    "AUDIT_PIPELINE_PERSISTENCE_CORRELATION_DUPLICATE",
    "AUDIT_PIPELINE_PERSISTENCE_CORRELATION_CONFLICT",
    "AUDIT_PIPELINE_PERSISTENCE_AUDIT_HASH_CONFLICT",
    "AUDIT_PIPELINE_PERSISTENCE_TENANT_CROSSOVER",
    "AUDIT_PIPELINE_PERSISTENCE_POLICY_VERSION_CROSSOVER",
    "AUDIT_PIPELINE_PERSISTENCE_STAGE_SEQUENCE_INVALID",
    "AUDIT_PIPELINE_PERSISTENCE_RAW_DATA_FORBIDDEN",
)
_RAW_MARKERS = (
    "raw_payload",
    "raw_evidence",
    "raw_approval",
    "credential",
    "credentials",
    "secret",
    "token",
    "private_key",
    "certificate",
)


class AuditPipelinePersistenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditPipelinePersistenceContext:
    evidence_id: str
    governance_decision: str
    persisted_at: str
    expected_previous_hash: str = AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH


@dataclass(frozen=True)
class AuditPipelinePersistenceResult:
    status: str
    errors: tuple[str, ...]
    persistence_hash: str
    record_hash: str
    previous_hash: str
    position: int
    correlation_id: str
    audit_hash: str
    governance_decision: str
    written: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "errors": list(self.errors),
            "persistence_hash": self.persistence_hash,
            "record_hash": self.record_hash,
            "previous_hash": self.previous_hash,
            "position": self.position,
            "correlation_id": self.correlation_id,
            "audit_hash": self.audit_hash,
            "governance_decision": self.governance_decision,
            "written": self.written,
            "execution_allowed": False,
            "provider_execution": False,
            "production_activation": False,
        }


def audit_pipeline_persistence_schema() -> dict[str, Any]:
    return {
        "schema": AUDIT_PIPELINE_PERSISTENCE_SCHEMA,
        "record_schema": AUDIT_PIPELINE_PERSISTENCE_RECORD_SCHEMA,
        "statuses": list(AUDIT_PIPELINE_PERSISTENCE_STATUSES),
        "errors": list(AUDIT_PIPELINE_PERSISTENCE_ERRORS),
        "payload_policy": "hash-only",
        "storage": "local-jsonl-append-only",
        "pipeline_stage_sequence": list(AUDIT_PIPELINE_STAGE_SEQUENCE),
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
    }


def build_pipeline_persistence_record(
    summary: AuditPipelineSummary | dict[str, Any],
    *,
    context: AuditPipelinePersistenceContext,
    previous_hash: str,
    position: int,
) -> dict[str, Any]:
    summary_payload = _summary_payload(summary)
    _validate_summary(summary_payload)
    _validate_context(context)
    if not _is_sha256_reference(previous_hash):
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_PREVIOUS_HASH_MISMATCH")
    if not isinstance(position, int) or position < 0:
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_POSITION_INVALID")
    if tuple(summary_payload.get("stage_sequence", ())) != AUDIT_PIPELINE_STAGE_SEQUENCE:
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_STAGE_SEQUENCE_INVALID")

    summary_hash = sha256_audit_hash(summary_payload)
    record_payload = {
        "schema": AUDIT_PIPELINE_PERSISTENCE_RECORD_SCHEMA,
        "position": position,
        "previous_hash": previous_hash,
        "correlation_id": summary_payload["correlation_id"],
        "tenant": summary_payload["tenant"],
        "policy_version": summary_payload["policy_version"],
        "evidence_id": context.evidence_id,
        "governance_decision": context.governance_decision,
        "persisted_at": context.persisted_at,
        "validator_sequence_hash": sha256_audit_hash(list(AUDIT_PIPELINE_STAGE_SEQUENCE)),
        "stage_count": summary_payload["stage_count"],
        "stage_hashes": list(summary_payload["stage_hashes"]),
        "canonical_payload_hashes": list(summary_payload["canonical_payload_hashes"]),
        "canonical_payload_hash": summary_hash,
        "audit_hash": sha256_audit_hash(
            {
                "correlation_id": summary_payload["correlation_id"],
                "tenant": summary_payload["tenant"],
                "policy_version": summary_payload["policy_version"],
                "evidence_id": context.evidence_id,
                "summary_hash": summary_hash,
                "governance_decision": context.governance_decision,
            }
        ),
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
    }
    record = {**record_payload, "record_hash": sha256_audit_hash(record_payload)}
    _assert_no_raw_markers(record)
    return record


def append_pipeline_summary_record(
    storage_path: Path,
    summary: AuditPipelineSummary | dict[str, Any],
    *,
    context: AuditPipelinePersistenceContext,
) -> AuditPipelinePersistenceResult:
    try:
        _validate_storage_path(storage_path)
        lock_path = storage_path.with_suffix(storage_path.suffix + ".lock")
        lock_fd = _acquire_lock(lock_path)
    except AuditPipelinePersistenceError as exc:
        return _blocked_result(str(exc), context=context if isinstance(context, AuditPipelinePersistenceContext) else None)
    try:
        records = load_pipeline_persistence_records(storage_path)
        verification = verify_pipeline_persistence_records(records)
        if verification:
            return _blocked_result(verification[0], context=context)
        if records:
            expected_previous = str(records[-1].get("record_hash", ""))
            if not context.expected_previous_hash:
                return _blocked_result("AUDIT_PIPELINE_PERSISTENCE_PREVIOUS_HASH_MISSING", context=context)
            if context.expected_previous_hash != expected_previous:
                return _blocked_result("AUDIT_PIPELINE_PERSISTENCE_PREVIOUS_HASH_MISMATCH", context=context)
        elif context.expected_previous_hash != AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH:
            return _blocked_result("AUDIT_PIPELINE_PERSISTENCE_PREVIOUS_HASH_MISMATCH", context=context)
        record = build_pipeline_persistence_record(
            summary,
            context=context,
            previous_hash=context.expected_previous_hash,
            position=len(records),
        )
        duplicate_result = _duplicate_result(records, record, context)
        if duplicate_result is not None:
            return duplicate_result
        _append_record(storage_path, record)
        after_records = load_pipeline_persistence_records(storage_path)
        after_verification = verify_pipeline_persistence_records(after_records)
        if after_verification:
            return _blocked_result(after_verification[0], context=context)
        return _result("PERSISTED", (), record, context, written=True)
    except AuditPipelinePersistenceError as exc:
        return _blocked_result(str(exc), context=context)
    finally:
        _release_lock(lock_fd, lock_path)


def load_pipeline_persistence_records(storage_path: Path) -> tuple[dict[str, Any], ...]:
    _validate_storage_path(storage_path)
    if not storage_path.exists():
        return ()
    records: list[dict[str, Any]] = []
    try:
        for line in storage_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_RECORD_MALFORMED")
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_RECORD_MALFORMED")
            records.append(payload)
    except json.JSONDecodeError as exc:
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_RECORD_MALFORMED") from exc
    except OSError as exc:
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_READ_FAILED") from exc
    return tuple(records)


def verify_pipeline_persistence_records(records: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> tuple[str, ...]:
    previous_hash = AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH
    seen_correlations: dict[str, dict[str, Any]] = {}
    seen_audit_hashes: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for expected_position, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append("AUDIT_PIPELINE_PERSISTENCE_RECORD_MALFORMED")
            continue
        try:
            _assert_no_raw_markers(record)
        except AuditPipelinePersistenceError:
            errors.append("AUDIT_PIPELINE_PERSISTENCE_RAW_DATA_FORBIDDEN")
        if record.get("schema") != AUDIT_PIPELINE_PERSISTENCE_RECORD_SCHEMA:
            errors.append("AUDIT_PIPELINE_PERSISTENCE_SCHEMA_INVALID")
        if record.get("position") != expected_position:
            errors.append("AUDIT_PIPELINE_PERSISTENCE_POSITION_INVALID")
        if record.get("previous_hash") != previous_hash:
            errors.append("AUDIT_PIPELINE_PERSISTENCE_PREVIOUS_HASH_MISMATCH")
        if tuple(record.get("stage_hashes", ())) and int(record.get("stage_count", -1)) != len(record.get("stage_hashes", ())):
            errors.append("AUDIT_PIPELINE_PERSISTENCE_SUMMARY_INVALID")
        if int(record.get("stage_count", -1)) != len(AUDIT_PIPELINE_STAGE_SEQUENCE):
            errors.append("AUDIT_PIPELINE_PERSISTENCE_SUMMARY_INVALID")
        for field in ("previous_hash", "correlation_id", "validator_sequence_hash", "canonical_payload_hash", "audit_hash", "record_hash"):
            if not _is_sha256_reference(record.get(field)):
                errors.append("AUDIT_PIPELINE_PERSISTENCE_HASH_INVALID")
        expected_record_hash = sha256_audit_hash({key: value for key, value in record.items() if key != "record_hash"})
        if record.get("record_hash") != expected_record_hash:
            errors.append("AUDIT_PIPELINE_PERSISTENCE_RECORD_HASH_MISMATCH")
        correlation_id = str(record.get("correlation_id", ""))
        audit_hash = str(record.get("audit_hash", ""))
        if correlation_id in seen_correlations:
            prior = seen_correlations[correlation_id]
            if prior == record:
                errors.append("AUDIT_PIPELINE_PERSISTENCE_CORRELATION_DUPLICATE")
            else:
                errors.append("AUDIT_PIPELINE_PERSISTENCE_CORRELATION_CONFLICT")
        seen_correlations[correlation_id] = dict(record)
        if audit_hash in seen_audit_hashes:
            prior = seen_audit_hashes[audit_hash]
            if prior.get("tenant") != record.get("tenant"):
                errors.append("AUDIT_PIPELINE_PERSISTENCE_TENANT_CROSSOVER")
            elif prior.get("policy_version") != record.get("policy_version"):
                errors.append("AUDIT_PIPELINE_PERSISTENCE_POLICY_VERSION_CROSSOVER")
            else:
                errors.append("AUDIT_PIPELINE_PERSISTENCE_AUDIT_HASH_CONFLICT")
        seen_audit_hashes[audit_hash] = dict(record)
        if record.get("execution_allowed") is not False or record.get("provider_execution") is not False or record.get("production_activation") is not False:
            errors.append("AUDIT_PIPELINE_PERSISTENCE_SUMMARY_INVALID")
        previous_hash = str(record.get("record_hash", ""))
    return _ordered_unique_errors(errors)


def _summary_payload(summary: AuditPipelineSummary | dict[str, Any]) -> dict[str, Any]:
    payload = summary.to_dict() if isinstance(summary, AuditPipelineSummary) else dict(summary)
    if "stage_sequence" not in payload:
        payload = {**payload, "stage_sequence": list(AUDIT_PIPELINE_STAGE_SEQUENCE)}
    return payload


def _validate_summary(summary: dict[str, Any]) -> None:
    if not summary.get("valid"):
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_SUMMARY_INVALID")
    required = ("correlation_id", "tenant", "policy_version", "stage_count", "stage_hashes", "canonical_payload_hashes")
    for field in required:
        if field not in summary or summary[field] in ("", None):
            raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_CONTEXT_MISSING")
    if summary.get("errors") not in ([], ()):
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_SUMMARY_INVALID")
    if int(summary["stage_count"]) != len(AUDIT_PIPELINE_STAGE_SEQUENCE):
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_SUMMARY_INVALID")
    stage_hashes = tuple(summary.get("stage_hashes", ()))
    canonical_hashes = tuple(summary.get("canonical_payload_hashes", ()))
    if len(stage_hashes) != len(AUDIT_PIPELINE_STAGE_SEQUENCE) or len(canonical_hashes) != len(AUDIT_PIPELINE_STAGE_SEQUENCE):
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_SUMMARY_INVALID")
    if not _is_sha256_reference(summary.get("correlation_id")):
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_HASH_INVALID")
    for value in (*stage_hashes, *canonical_hashes):
        if not _is_sha256_reference(value):
            raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_HASH_INVALID")
    serialize_audit_pipeline_summary({key: value for key, value in summary.items() if key != "stage_sequence"})


def _validate_context(context: AuditPipelinePersistenceContext) -> None:
    required = {
        "evidence_id": context.evidence_id,
        "governance_decision": context.governance_decision,
        "persisted_at": context.persisted_at,
    }
    for value in required.values():
        if not isinstance(value, str) or not value.strip():
            raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_CONTEXT_MISSING")
    if context.governance_decision not in {"ALLOWED", "BLOCKED", "REVIEW_REQUIRED"}:
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_CONTEXT_MISSING")
    if not _is_sha256_reference(context.expected_previous_hash):
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_PREVIOUS_HASH_MISMATCH")
    _assert_no_raw_markers(context.__dict__)


def _duplicate_result(
    records: tuple[dict[str, Any], ...],
    record: dict[str, Any],
    context: AuditPipelinePersistenceContext,
) -> AuditPipelinePersistenceResult | None:
    for existing in records:
        if existing.get("correlation_id") == record["correlation_id"]:
            if existing == {**record, "position": existing.get("position"), "previous_hash": existing.get("previous_hash"), "record_hash": existing.get("record_hash")}:
                return _result("ALREADY_PERSISTED", (), existing, context, written=False)
            if _idempotent_match(existing, record):
                return _result("ALREADY_PERSISTED", (), existing, context, written=False)
            return _result(
                "BLOCKED",
                ("AUDIT_PIPELINE_PERSISTENCE_CORRELATION_CONFLICT",),
                record,
                context,
                written=False,
            )
        if existing.get("audit_hash") == record["audit_hash"]:
            if existing.get("tenant") != record["tenant"]:
                error = "AUDIT_PIPELINE_PERSISTENCE_TENANT_CROSSOVER"
            elif existing.get("policy_version") != record["policy_version"]:
                error = "AUDIT_PIPELINE_PERSISTENCE_POLICY_VERSION_CROSSOVER"
            else:
                error = "AUDIT_PIPELINE_PERSISTENCE_AUDIT_HASH_CONFLICT"
            return _result("BLOCKED", (error,), record, context, written=False)
    return None


def _idempotent_match(existing: dict[str, Any], record: dict[str, Any]) -> bool:
    comparable = (
        "correlation_id",
        "tenant",
        "policy_version",
        "evidence_id",
        "governance_decision",
        "validator_sequence_hash",
        "stage_count",
        "stage_hashes",
        "canonical_payload_hashes",
        "canonical_payload_hash",
        "audit_hash",
        "execution_allowed",
        "provider_execution",
        "production_activation",
    )
    return all(existing.get(key) == record.get(key) for key in comparable)


def _append_record(storage_path: Path, record: dict[str, Any]) -> None:
    try:
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        with storage_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_audit_json(record) + "\n")
    except OSError as exc:
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_WRITE_FAILED") from exc


def _validate_storage_path(storage_path: Path) -> None:
    if not isinstance(storage_path, Path):
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_PATH_INVALID")
    if storage_path.name in {"", ".", ".."}:
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_PATH_INVALID")


def _acquire_lock(lock_path: Path) -> int:
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        return os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_LOCKED") from exc
    except OSError as exc:
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_WRITE_FAILED") from exc


def _release_lock(lock_fd: int | None, lock_path: Path) -> None:
    if lock_fd is not None:
        os.close(lock_fd)
    try:
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass


def _result(
    status: str,
    errors: tuple[str, ...],
    record: dict[str, Any],
    context: AuditPipelinePersistenceContext,
    *,
    written: bool,
) -> AuditPipelinePersistenceResult:
    return AuditPipelinePersistenceResult(
        status=status,
        errors=errors,
        persistence_hash=sha256_audit_hash(
            {
                "status": status,
                "errors": list(errors),
                "record_hash": record.get("record_hash", ""),
                "written": written,
            }
        ),
        record_hash=str(record.get("record_hash", "")),
        previous_hash=str(record.get("previous_hash", "")),
        position=int(record.get("position", -1)),
        correlation_id=str(record.get("correlation_id", "")),
        audit_hash=str(record.get("audit_hash", "")),
        governance_decision=context.governance_decision,
        written=written,
    )


def _blocked_result(error: str, *, context: AuditPipelinePersistenceContext | None) -> AuditPipelinePersistenceResult:
    return AuditPipelinePersistenceResult(
        status="BLOCKED",
        errors=(error,),
        persistence_hash=sha256_audit_hash({"status": "BLOCKED", "errors": [error]}),
        record_hash="",
        previous_hash=context.expected_previous_hash if context else "",
        position=-1,
        correlation_id="",
        audit_hash="",
        governance_decision=context.governance_decision if context else "",
        written=False,
    )


def _ordered_unique_errors(errors: list[str]) -> tuple[str, ...]:
    return tuple(code for code in AUDIT_PIPELINE_PERSISTENCE_ERRORS if code in errors)


def _is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _assert_no_raw_markers(payload: Any) -> None:
    serialized = canonical_audit_json(payload)
    lowered = serialized.lower()
    if any(marker in lowered for marker in _RAW_MARKERS):
        raise AuditPipelinePersistenceError("AUDIT_PIPELINE_PERSISTENCE_RAW_DATA_FORBIDDEN")
