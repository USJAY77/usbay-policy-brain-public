from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.audit_evidence import AUDIT_PIPELINE_STAGE_SEQUENCE, AuditPipelineSummary, canonical_audit_json, sha256_audit_hash
from governance.audit_evidence_persistence import (
    AUDIT_PIPELINE_PERSISTENCE_RECORD_SCHEMA,
    verify_pipeline_persistence_records,
)
from governance.runtime_ledger import (
    GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH,
    GOVERNANCE_RUNTIME_LEDGER_ENTRY_SCHEMA,
    build_runtime_ledger_entry,
    verify_runtime_ledger,
)


RUNTIME_LEDGER_PERSISTENCE_SCHEMA = "usbay.governance.runtime_ledger_persistence.v1"
RUNTIME_LEDGER_PERSISTENCE_RECORD_SCHEMA = RUNTIME_LEDGER_PERSISTENCE_SCHEMA + ".record"
RUNTIME_LEDGER_RECONCILIATION_SCHEMA = RUNTIME_LEDGER_PERSISTENCE_SCHEMA + ".reconciliation"
RUNTIME_LEDGER_PERSISTENCE_STATUSES = (
    "PERSISTED",
    "ALREADY_PERSISTED",
    "BLOCKED",
)
RUNTIME_LEDGER_RECONCILIATION_STATES = (
    "CONSISTENT",
    "ALREADY_RECONCILED",
    "AUDIT_RECORD_MISSING",
    "LEDGER_RECORD_MISSING",
    "CORRELATION_CONFLICT",
    "TENANT_MISMATCH",
    "POLICY_VERSION_MISMATCH",
    "EVIDENCE_ID_MISMATCH",
    "AUDIT_HASH_MISMATCH",
    "DECISION_MISMATCH",
    "FAILURE_CODE_MISMATCH",
    "PREVIOUS_HASH_MISMATCH",
    "DUPLICATE_RECORD",
    "MALFORMED_RECORD",
    "INCOMPLETE_CONTEXT",
    "STORAGE_FAILURE",
)
RUNTIME_LEDGER_PERSISTENCE_ERRORS = (
    "RUNTIME_LEDGER_PERSISTENCE_PATH_INVALID",
    "RUNTIME_LEDGER_PERSISTENCE_LOCKED",
    "RUNTIME_LEDGER_PERSISTENCE_READ_FAILED",
    "RUNTIME_LEDGER_PERSISTENCE_WRITE_FAILED",
    *RUNTIME_LEDGER_RECONCILIATION_STATES[2:],
)
_RAW_MARKERS = (
    "raw_payload",
    "raw_evidence",
    "raw_approval",
    "payload_body",
    "prompt",
    "signature_body",
    "certificate",
    "private_key",
    "credential",
    "credentials",
    "secret",
    "token",
)


class RuntimeLedgerPersistenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeLedgerPersistenceContext:
    checked_at: str
    expected_previous_hash: str = GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH


@dataclass(frozen=True)
class RuntimeLedgerPersistenceResult:
    status: str
    errors: tuple[str, ...]
    record_hash: str
    previous_hash: str
    position: int
    reconciliation_id: str
    correlation_id: str
    audit_record_hash: str
    ledger_record_hash: str
    written: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "errors": list(self.errors),
            "record_hash": self.record_hash,
            "previous_hash": self.previous_hash,
            "position": self.position,
            "reconciliation_id": self.reconciliation_id,
            "correlation_id": self.correlation_id,
            "audit_record_hash": self.audit_record_hash,
            "ledger_record_hash": self.ledger_record_hash,
            "written": self.written,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class RuntimeLedgerReconciliationResult:
    result: str
    failure_code: str
    errors: tuple[str, ...]
    reconciliation_id: str
    correlation_id: str
    tenant: str
    policy_version: str
    evidence_id: str
    audit_record_hash: str
    ledger_record_hash: str
    audit_chain_position: int
    ledger_chain_position: int
    report_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": RUNTIME_LEDGER_RECONCILIATION_SCHEMA,
            "result": self.result,
            "failure_code": self.failure_code,
            "errors": list(self.errors),
            "reconciliation_id": self.reconciliation_id,
            "correlation_id": self.correlation_id,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "evidence_id": self.evidence_id,
            "audit_record_hash": self.audit_record_hash,
            "ledger_record_hash": self.ledger_record_hash,
            "audit_chain_position": self.audit_chain_position,
            "ledger_chain_position": self.ledger_chain_position,
            "report_hash": self.report_hash,
            **_false_execution_flags(),
        }


def runtime_ledger_persistence_schema() -> dict[str, Any]:
    return {
        "schema": RUNTIME_LEDGER_PERSISTENCE_SCHEMA,
        "record_schema": RUNTIME_LEDGER_PERSISTENCE_RECORD_SCHEMA,
        "reconciliation_schema": RUNTIME_LEDGER_RECONCILIATION_SCHEMA,
        "statuses": list(RUNTIME_LEDGER_PERSISTENCE_STATUSES),
        "reconciliation_states": list(RUNTIME_LEDGER_RECONCILIATION_STATES),
        "errors": list(RUNTIME_LEDGER_PERSISTENCE_ERRORS),
        "payload_policy": "hash-only",
        "storage": "local-jsonl-append-only",
        **_false_execution_flags(),
    }


def build_runtime_ledger_persistence_record(
    ledger_entry: dict[str, Any],
    audit_record: dict[str, Any],
    *,
    context: RuntimeLedgerPersistenceContext,
    previous_hash: str,
    position: int,
) -> dict[str, Any]:
    _validate_context(context)
    _validate_audit_record(audit_record)
    _validate_ledger_entry(ledger_entry)
    if not _is_sha256_reference(previous_hash):
        raise RuntimeLedgerPersistenceError("PREVIOUS_HASH_MISMATCH")
    if not isinstance(position, int) or position < 0:
        raise RuntimeLedgerPersistenceError("MALFORMED_RECORD")
    reconciliation = reconcile_runtime_ledger_references(
        audit_record=audit_record,
        ledger_entry=ledger_entry,
        stored_ledger_record=None,
        checked_at=context.checked_at,
    )
    if reconciliation.result != "CONSISTENT":
        raise RuntimeLedgerPersistenceError(reconciliation.result)
    record_payload = {
        "schema": RUNTIME_LEDGER_PERSISTENCE_RECORD_SCHEMA,
        "position": position,
        "previous_hash": previous_hash,
        "reconciliation_id": reconciliation.reconciliation_id,
        "correlation_id": ledger_entry["correlation_id"],
        "tenant": ledger_entry["tenant"],
        "policy_version": ledger_entry["policy_version"],
        "evidence_id": ledger_entry["evidence_id"],
        "governance_decision": ledger_entry["decision"],
        "failure_code": ledger_entry["failure_code"],
        "audit_hash": ledger_entry["audit_hash"],
        "canonical_payload_hash": audit_record["canonical_payload_hash"],
        "audit_record_hash": audit_record["record_hash"],
        "ledger_id": ledger_entry["ledger_id"],
        "ledger_entry_hash": ledger_entry["entry_hash"],
        "ledger_previous_hash": ledger_entry["previous_hash"],
        "audit_chain_position": int(audit_record["position"]),
        "ledger_chain_position": position,
        "checked_at": context.checked_at,
        **_false_execution_flags(),
    }
    record = {**record_payload, "record_hash": sha256_audit_hash(record_payload)}
    _assert_no_raw_markers(record)
    return record


def append_runtime_ledger_persistence_record(
    storage_path: Path,
    ledger_entry: dict[str, Any],
    audit_record: dict[str, Any],
    *,
    context: RuntimeLedgerPersistenceContext,
) -> RuntimeLedgerPersistenceResult:
    try:
        _validate_storage_path(storage_path)
        lock_path = storage_path.with_suffix(storage_path.suffix + ".lock")
        lock_fd = _acquire_lock(lock_path)
    except RuntimeLedgerPersistenceError as exc:
        return _blocked_result(str(exc))
    try:
        records = load_runtime_ledger_persistence_records(storage_path)
        verification = verify_runtime_ledger_persistence_records(records)
        if verification:
            return _blocked_result(verification[0])
        if records:
            expected_previous = str(records[-1].get("record_hash", ""))
            if context.expected_previous_hash != expected_previous:
                return _blocked_result("PREVIOUS_HASH_MISMATCH")
        elif context.expected_previous_hash != GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH:
            return _blocked_result("PREVIOUS_HASH_MISMATCH")
        record = build_runtime_ledger_persistence_record(
            ledger_entry,
            audit_record,
            context=context,
            previous_hash=context.expected_previous_hash,
            position=len(records),
        )
        duplicate = _duplicate_result(records, record)
        if duplicate is not None:
            return duplicate
        _append_record(storage_path, record)
        after_records = load_runtime_ledger_persistence_records(storage_path)
        after_verification = verify_runtime_ledger_persistence_records(after_records)
        if after_verification:
            return _blocked_result(after_verification[0])
        return _persistence_result("PERSISTED", (), record, written=True)
    except RuntimeLedgerPersistenceError as exc:
        return _blocked_result(str(exc))
    finally:
        _release_lock(lock_fd, lock_path)


def load_runtime_ledger_persistence_records(storage_path: Path) -> tuple[dict[str, Any], ...]:
    _validate_storage_path(storage_path)
    if not storage_path.exists():
        return ()
    records: list[dict[str, Any]] = []
    try:
        for line in storage_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                raise RuntimeLedgerPersistenceError("MALFORMED_RECORD")
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise RuntimeLedgerPersistenceError("MALFORMED_RECORD")
            records.append(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeLedgerPersistenceError("MALFORMED_RECORD") from exc
    except OSError as exc:
        raise RuntimeLedgerPersistenceError("STORAGE_FAILURE") from exc
    return tuple(records)


def verify_runtime_ledger_persistence_records(records: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> tuple[str, ...]:
    if not isinstance(records, (tuple, list)):
        return ("MALFORMED_RECORD",)
    errors: list[str] = []
    previous_hash = GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH
    seen_correlations: dict[str, dict[str, Any]] = {}
    seen_audit_hashes: dict[str, dict[str, Any]] = {}
    seen_evidence_ids: dict[str, dict[str, Any]] = {}
    for expected_position, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append("MALFORMED_RECORD")
            continue
        try:
            _assert_no_raw_markers(record)
        except RuntimeLedgerPersistenceError:
            errors.append("MALFORMED_RECORD")
        if record.get("schema") != RUNTIME_LEDGER_PERSISTENCE_RECORD_SCHEMA:
            errors.append("MALFORMED_RECORD")
        if record.get("position") != expected_position or record.get("ledger_chain_position") != expected_position:
            errors.append("MALFORMED_RECORD")
        if record.get("previous_hash") != previous_hash:
            errors.append("PREVIOUS_HASH_MISMATCH")
        for field in (
            "previous_hash",
            "reconciliation_id",
            "correlation_id",
            "audit_hash",
            "canonical_payload_hash",
            "audit_record_hash",
            "ledger_id",
            "ledger_entry_hash",
            "ledger_previous_hash",
            "record_hash",
        ):
            if not _is_sha256_reference(record.get(field)):
                errors.append("MALFORMED_RECORD")
        if _missing_record_context(record):
            errors.append("INCOMPLETE_CONTEXT")
        expected_hash = sha256_audit_hash({key: value for key, value in record.items() if key != "record_hash"})
        if record.get("record_hash") != expected_hash:
            errors.append("MALFORMED_RECORD")
        correlation_id = str(record.get("correlation_id", ""))
        audit_hash = str(record.get("audit_hash", ""))
        evidence_id = str(record.get("evidence_id", ""))
        if correlation_id in seen_correlations:
            prior = seen_correlations[correlation_id]
            if _same_logical_record(prior, record):
                errors.append("DUPLICATE_RECORD")
            else:
                errors.append("CORRELATION_CONFLICT")
        seen_correlations[correlation_id] = dict(record)
        if audit_hash in seen_audit_hashes:
            prior = seen_audit_hashes[audit_hash]
            if prior.get("tenant") != record.get("tenant"):
                errors.append("TENANT_MISMATCH")
            elif prior.get("policy_version") != record.get("policy_version"):
                errors.append("POLICY_VERSION_MISMATCH")
            else:
                errors.append("DUPLICATE_RECORD")
        seen_audit_hashes[audit_hash] = dict(record)
        if evidence_id in seen_evidence_ids:
            prior = seen_evidence_ids[evidence_id]
            if prior.get("policy_version") != record.get("policy_version"):
                errors.append("POLICY_VERSION_MISMATCH")
        seen_evidence_ids[evidence_id] = dict(record)
        if any(record.get(flag) is not False for flag in _EXECUTION_FLAG_NAMES):
            errors.append("MALFORMED_RECORD")
        previous_hash = str(record.get("record_hash", ""))
    return _ordered_unique_errors(errors)


def reconcile_runtime_ledger_references(
    *,
    audit_record: dict[str, Any] | None,
    ledger_entry: dict[str, Any] | None,
    stored_ledger_record: dict[str, Any] | None,
    checked_at: str,
    summary: AuditPipelineSummary | dict[str, Any] | None = None,
) -> RuntimeLedgerReconciliationResult:
    errors: list[str] = []
    if not isinstance(checked_at, str) or not checked_at.strip():
        errors.append("INCOMPLETE_CONTEXT")
    if audit_record is None:
        errors.append("AUDIT_RECORD_MISSING")
        audit_record = {}
    if ledger_entry is None:
        errors.append("LEDGER_RECORD_MISSING")
        ledger_entry = {}
    if stored_ledger_record is not None:
        stored_errors = verify_runtime_ledger_persistence_records((stored_ledger_record,))
        if stored_errors:
            errors.append("MALFORMED_RECORD")
    try:
        if audit_record:
            _validate_audit_record(audit_record)
    except RuntimeLedgerPersistenceError as exc:
        errors.append("MALFORMED_RECORD" if str(exc) != "AUDIT_RECORD_MISSING" else "AUDIT_RECORD_MISSING")
    try:
        if ledger_entry:
            _validate_ledger_entry(ledger_entry)
    except RuntimeLedgerPersistenceError:
        errors.append("MALFORMED_RECORD")
    if audit_record and ledger_entry:
        _compare("correlation_id", audit_record, ledger_entry, "CORRELATION_CONFLICT", errors)
        _compare("tenant", audit_record, ledger_entry, "TENANT_MISMATCH", errors)
        _compare("policy_version", audit_record, ledger_entry, "POLICY_VERSION_MISMATCH", errors)
        _compare("evidence_id", audit_record, ledger_entry, "EVIDENCE_ID_MISMATCH", errors)
        _compare("audit_hash", audit_record, ledger_entry, "AUDIT_HASH_MISMATCH", errors)
        if audit_record.get("governance_decision") != ledger_entry.get("decision"):
            errors.append("DECISION_MISMATCH")
        if str(ledger_entry.get("failure_code", "")) and str(audit_record.get("governance_decision", "")) == "ALLOWED":
            errors.append("FAILURE_CODE_MISMATCH")
    if summary is not None:
        summary_payload = summary.to_dict() if isinstance(summary, AuditPipelineSummary) else dict(summary)
        summary_hash_payload = {**summary_payload, "stage_sequence": summary_payload.get("stage_sequence", list(AUDIT_PIPELINE_STAGE_SEQUENCE))}
        if summary_payload.get("correlation_id") != audit_record.get("correlation_id"):
            errors.append("CORRELATION_CONFLICT")
        if summary_payload.get("tenant") != audit_record.get("tenant"):
            errors.append("TENANT_MISMATCH")
        if summary_payload.get("policy_version") != audit_record.get("policy_version"):
            errors.append("POLICY_VERSION_MISMATCH")
        if sha256_audit_hash(summary_hash_payload) != audit_record.get("canonical_payload_hash"):
            if audit_record.get("canonical_payload_hash"):
                errors.append("AUDIT_HASH_MISMATCH")
    if stored_ledger_record is not None:
        if stored_ledger_record.get("audit_record_hash") != audit_record.get("record_hash"):
            errors.append("AUDIT_HASH_MISMATCH")
        if stored_ledger_record.get("ledger_entry_hash") != ledger_entry.get("entry_hash"):
            errors.append("LEDGER_RECORD_MISSING")
        if stored_ledger_record.get("ledger_previous_hash") != ledger_entry.get("previous_hash"):
            errors.append("PREVIOUS_HASH_MISMATCH")
        for field, code in (
            ("correlation_id", "CORRELATION_CONFLICT"),
            ("tenant", "TENANT_MISMATCH"),
            ("policy_version", "POLICY_VERSION_MISMATCH"),
            ("evidence_id", "EVIDENCE_ID_MISMATCH"),
            ("audit_hash", "AUDIT_HASH_MISMATCH"),
        ):
            _compare(field, stored_ledger_record, ledger_entry, code, errors)
        if stored_ledger_record.get("governance_decision") != ledger_entry.get("decision"):
            errors.append("DECISION_MISMATCH")
        if stored_ledger_record.get("failure_code") != ledger_entry.get("failure_code"):
            errors.append("FAILURE_CODE_MISMATCH")
    return _reconciliation_result(_ordered_unique_errors(errors), audit_record, ledger_entry, stored_ledger_record, checked_at)


def reconcile_runtime_ledger_sets(
    *,
    audit_records: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    ledger_records: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    checked_at: str,
) -> RuntimeLedgerReconciliationResult:
    audit_errors = verify_pipeline_persistence_records(tuple(audit_records))
    ledger_errors = verify_runtime_ledger_persistence_records(tuple(ledger_records))
    errors: list[str] = list(ledger_errors)
    if audit_errors:
        errors.append("MALFORMED_RECORD")
    audits_by_correlation = {str(record.get("correlation_id", "")): record for record in audit_records if isinstance(record, dict)}
    ledgers_by_correlation = {str(record.get("correlation_id", "")): record for record in ledger_records if isinstance(record, dict)}
    for correlation_id in sorted(set(audits_by_correlation) - set(ledgers_by_correlation)):
        if correlation_id:
            errors.append("LEDGER_RECORD_MISSING")
    for correlation_id in sorted(set(ledgers_by_correlation) - set(audits_by_correlation)):
        if correlation_id:
            errors.append("AUDIT_RECORD_MISSING")
    first_audit = next(iter(audits_by_correlation.values()), None)
    first_ledger_record = next(iter(ledgers_by_correlation.values()), None)
    ledger_entry = _ledger_entry_from_record(first_ledger_record) if first_ledger_record else None
    return _reconciliation_result(_ordered_unique_errors(errors), first_audit or {}, ledger_entry or {}, first_ledger_record, checked_at)


def _ledger_entry_from_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "usbay.governance.runtime_ledger.v1.entry",
        "ledger_id": record.get("ledger_id", ""),
        "position": record.get("ledger_chain_position", -1),
        "timestamp": record.get("checked_at", ""),
        "tenant": record.get("tenant", ""),
        "policy_version": record.get("policy_version", ""),
        "validator": "audit_pipeline",
        "decision": record.get("governance_decision", ""),
        "failure_code": record.get("failure_code", ""),
        "evidence_id": record.get("evidence_id", ""),
        "audit_hash": record.get("audit_hash", ""),
        "previous_hash": record.get("ledger_previous_hash", ""),
        "correlation_id": record.get("correlation_id", ""),
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "entry_hash": record.get("ledger_entry_hash", ""),
    }


def _validate_audit_record(record: dict[str, Any]) -> None:
    if not isinstance(record, dict) or record.get("schema") != AUDIT_PIPELINE_PERSISTENCE_RECORD_SCHEMA:
        raise RuntimeLedgerPersistenceError("AUDIT_RECORD_MISSING")
    if verify_pipeline_persistence_records((record,)):
        raise RuntimeLedgerPersistenceError("MALFORMED_RECORD")


def _validate_ledger_entry(entry: dict[str, Any]) -> None:
    if not isinstance(entry, dict) or entry.get("schema") != GOVERNANCE_RUNTIME_LEDGER_ENTRY_SCHEMA:
        raise RuntimeLedgerPersistenceError("MALFORMED_RECORD")
    if any(entry.get(field) in ("", None) for field in ("ledger_id", "tenant", "policy_version", "decision", "evidence_id", "audit_hash", "previous_hash", "correlation_id", "entry_hash")):
        raise RuntimeLedgerPersistenceError("MALFORMED_RECORD")
    for field in ("ledger_id", "audit_hash", "previous_hash", "correlation_id", "entry_hash"):
        if not _is_sha256_reference(entry.get(field)):
            raise RuntimeLedgerPersistenceError("MALFORMED_RECORD")
    expected_ledger_id = sha256_audit_hash(
        {
            "schema": GOVERNANCE_RUNTIME_LEDGER_ENTRY_SCHEMA,
            "timestamp": str(entry.get("timestamp", "")),
            "tenant": str(entry.get("tenant", "")),
            "policy_version": str(entry.get("policy_version", "")),
            "validator": str(entry.get("validator", "")),
            "decision": str(entry.get("decision", "")),
            "failure_code": str(entry.get("failure_code", "")),
            "evidence_id": str(entry.get("evidence_id", "")),
            "audit_hash": str(entry.get("audit_hash", "")),
            "correlation_id": str(entry.get("correlation_id", "")),
        }
    )
    expected_entry_hash = sha256_audit_hash({key: value for key, value in entry.items() if key != "entry_hash"})
    if entry.get("ledger_id") != expected_ledger_id or entry.get("entry_hash") != expected_entry_hash:
        raise RuntimeLedgerPersistenceError("MALFORMED_RECORD")
    if any(entry.get(flag) is not False for flag in ("execution_allowed", "provider_execution", "production_activation")):
        raise RuntimeLedgerPersistenceError("MALFORMED_RECORD")


def _validate_context(context: RuntimeLedgerPersistenceContext) -> None:
    if not isinstance(context.checked_at, str) or not context.checked_at.strip():
        raise RuntimeLedgerPersistenceError("INCOMPLETE_CONTEXT")
    if not _is_sha256_reference(context.expected_previous_hash):
        raise RuntimeLedgerPersistenceError("PREVIOUS_HASH_MISMATCH")
    _assert_no_raw_markers(context.__dict__)


def _append_record(storage_path: Path, record: dict[str, Any]) -> None:
    try:
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        with storage_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_audit_json(record) + "\n")
    except OSError as exc:
        raise RuntimeLedgerPersistenceError("STORAGE_FAILURE") from exc


def _validate_storage_path(storage_path: Path) -> None:
    if not isinstance(storage_path, Path) or storage_path.name in {"", ".", ".."}:
        raise RuntimeLedgerPersistenceError("RUNTIME_LEDGER_PERSISTENCE_PATH_INVALID")


def _acquire_lock(lock_path: Path) -> int:
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        return os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeLedgerPersistenceError("RUNTIME_LEDGER_PERSISTENCE_LOCKED") from exc
    except OSError as exc:
        raise RuntimeLedgerPersistenceError("STORAGE_FAILURE") from exc


def _release_lock(lock_fd: int | None, lock_path: Path) -> None:
    if lock_fd is not None:
        os.close(lock_fd)
    try:
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass


def _duplicate_result(
    records: tuple[dict[str, Any], ...],
    record: dict[str, Any],
) -> RuntimeLedgerPersistenceResult | None:
    for existing in records:
        if existing.get("correlation_id") == record["correlation_id"]:
            if _same_logical_record(existing, record):
                return _persistence_result("ALREADY_PERSISTED", (), existing, written=False)
            return _persistence_result("BLOCKED", ("CORRELATION_CONFLICT",), record, written=False)
        if existing.get("audit_hash") == record["audit_hash"]:
            if existing.get("tenant") != record["tenant"]:
                error = "TENANT_MISMATCH"
            elif existing.get("policy_version") != record["policy_version"]:
                error = "POLICY_VERSION_MISMATCH"
            else:
                error = "DUPLICATE_RECORD"
            return _persistence_result("BLOCKED", (error,), record, written=False)
    return None


def _same_logical_record(left: dict[str, Any], right: dict[str, Any]) -> bool:
    fields = (
        "reconciliation_id",
        "correlation_id",
        "tenant",
        "policy_version",
        "evidence_id",
        "governance_decision",
        "failure_code",
        "audit_hash",
        "canonical_payload_hash",
        "audit_record_hash",
        "ledger_id",
        "ledger_entry_hash",
        "ledger_previous_hash",
    )
    return all(left.get(field) == right.get(field) for field in fields)


def _persistence_result(
    status: str,
    errors: tuple[str, ...],
    record: dict[str, Any],
    *,
    written: bool,
) -> RuntimeLedgerPersistenceResult:
    return RuntimeLedgerPersistenceResult(
        status=status,
        errors=errors,
        record_hash=str(record.get("record_hash", "")),
        previous_hash=str(record.get("previous_hash", "")),
        position=int(record.get("position", -1)),
        reconciliation_id=str(record.get("reconciliation_id", "")),
        correlation_id=str(record.get("correlation_id", "")),
        audit_record_hash=str(record.get("audit_record_hash", "")),
        ledger_record_hash=str(record.get("ledger_entry_hash", "")),
        written=written,
    )


def _blocked_result(error: str) -> RuntimeLedgerPersistenceResult:
    return RuntimeLedgerPersistenceResult(
        status="BLOCKED",
        errors=(error,),
        record_hash="",
        previous_hash="",
        position=-1,
        reconciliation_id="",
        correlation_id="",
        audit_record_hash="",
        ledger_record_hash="",
        written=False,
    )


def _reconciliation_result(
    errors: tuple[str, ...],
    audit_record: dict[str, Any],
    ledger_entry: dict[str, Any],
    stored_ledger_record: dict[str, Any] | None,
    checked_at: str,
) -> RuntimeLedgerReconciliationResult:
    result = "CONSISTENT" if not errors else errors[0]
    report_payload = {
        "schema": RUNTIME_LEDGER_RECONCILIATION_SCHEMA,
        "result": result,
        "failure_code": "" if result == "CONSISTENT" else result,
        "errors": list(errors),
        "correlation_id": str((stored_ledger_record or ledger_entry or audit_record).get("correlation_id", "")),
        "tenant": str((stored_ledger_record or ledger_entry or audit_record).get("tenant", "")),
        "policy_version": str((stored_ledger_record or ledger_entry or audit_record).get("policy_version", "")),
        "evidence_id": str((stored_ledger_record or ledger_entry or audit_record).get("evidence_id", "")),
        "audit_record_hash": str(audit_record.get("record_hash", "") or (stored_ledger_record or {}).get("audit_record_hash", "")),
        "ledger_record_hash": str((stored_ledger_record or {}).get("ledger_entry_hash", "") or ledger_entry.get("entry_hash", "")),
        "audit_chain_position": int(audit_record.get("position", -1)) if str(audit_record.get("position", "")).lstrip("-").isdigit() else -1,
        "ledger_chain_position": int((stored_ledger_record or ledger_entry).get("position", -1))
        if str((stored_ledger_record or ledger_entry).get("position", "")).lstrip("-").isdigit()
        else -1,
        "checked_at": checked_at,
        **_false_execution_flags(),
    }
    reconciliation_id = sha256_audit_hash({key: value for key, value in report_payload.items() if key != "checked_at"})
    final_payload = {**report_payload, "reconciliation_id": reconciliation_id}
    return RuntimeLedgerReconciliationResult(
        result=result,
        failure_code="" if result == "CONSISTENT" else result,
        errors=errors,
        reconciliation_id=reconciliation_id,
        correlation_id=final_payload["correlation_id"],
        tenant=final_payload["tenant"],
        policy_version=final_payload["policy_version"],
        evidence_id=final_payload["evidence_id"],
        audit_record_hash=final_payload["audit_record_hash"],
        ledger_record_hash=final_payload["ledger_record_hash"],
        audit_chain_position=final_payload["audit_chain_position"],
        ledger_chain_position=final_payload["ledger_chain_position"],
        report_hash=sha256_audit_hash(final_payload),
    )


def _compare(field: str, left: dict[str, Any], right: dict[str, Any], code: str, errors: list[str]) -> None:
    if left.get(field) != right.get(field):
        errors.append(code)


def _missing_record_context(record: dict[str, Any]) -> bool:
    required = (
        "reconciliation_id",
        "correlation_id",
        "tenant",
        "policy_version",
        "evidence_id",
        "governance_decision",
        "audit_hash",
        "canonical_payload_hash",
        "audit_record_hash",
        "ledger_id",
        "ledger_entry_hash",
    )
    return any(record.get(field) in ("", None) for field in required)


def _ordered_unique_errors(errors: list[str]) -> tuple[str, ...]:
    return tuple(code for code in RUNTIME_LEDGER_RECONCILIATION_STATES[2:] if code in errors)


_EXECUTION_FLAG_NAMES = (
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "runtime_execution",
    "deployment_execution",
    "policy_mutation",
    "network_access",
)


def _false_execution_flags() -> dict[str, bool]:
    return {name: False for name in _EXECUTION_FLAG_NAMES}


def _is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _assert_no_raw_markers(payload: Any) -> None:
    serialized = canonical_audit_json(payload)
    lowered = serialized.lower()
    if any(marker in lowered for marker in _RAW_MARKERS):
        raise RuntimeLedgerPersistenceError("MALFORMED_RECORD")
