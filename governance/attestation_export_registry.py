from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.audit_evidence import ZERO_AUDIT_CHAIN_HASH, canonical_audit_json, sha256_audit_hash
from governance.reconciliation_attestation import (
    RECONCILIATION_ATTESTATION_SCHEMA,
    RECONCILIATION_EXPORT_BUNDLE_SCHEMA,
    verify_reconciliation_attestation,
    verify_regulator_export_bundle,
)


ATTESTATION_EXPORT_REGISTRY_SCHEMA = "usbay.governance.attestation_export_registry.v1"
ATTESTATION_REGISTRY_RECORD_SCHEMA = ATTESTATION_EXPORT_REGISTRY_SCHEMA + ".attestation_record"
EXPORT_BUNDLE_REGISTRY_RECORD_SCHEMA = ATTESTATION_EXPORT_REGISTRY_SCHEMA + ".export_bundle_record"
CROSS_REGISTRY_REPORT_SCHEMA = ATTESTATION_EXPORT_REGISTRY_SCHEMA + ".cross_registry_report"
REGISTRY_GENESIS_HASH = ZERO_AUDIT_CHAIN_HASH
REGISTRY_STATUSES = (
    "PERSISTED",
    "ALREADY_PERSISTED",
    "REGISTRY_VALID",
    "ATTESTATION_REQUIRED",
    "ATTESTATION_INVALID",
    "EXPORT_BUNDLE_INVALID",
    "HASH_MISMATCH",
    "REFERENCE_MISMATCH",
    "TENANT_MISMATCH",
    "POLICY_VERSION_MISMATCH",
    "EVIDENCE_ID_MISMATCH",
    "DECISION_MISMATCH",
    "FAILURE_CODE_MISMATCH",
    "DUPLICATE_RECORD",
    "RECORD_CONFLICT",
    "ORPHAN_REFERENCE",
    "CHAIN_INVALID",
    "REGISTRY_TAMPERED",
    "REGISTRY_TRUNCATED",
    "REGISTRY_REORDERED",
    "MALFORMED_RECORD",
    "LOCKED",
    "SERIALIZATION_FAILURE",
    "FAILED_CLOSED",
)
CROSS_REGISTRY_STATES = (
    "CONSISTENT",
    "AUDIT_RECORD_MISSING",
    "LEDGER_RECORD_MISSING",
    "ATTESTATION_MISSING",
    "EXPORT_RECORD_MISSING",
    "HASH_MISMATCH",
    "REFERENCE_MISMATCH",
    "TENANT_MISMATCH",
    "POLICY_VERSION_MISMATCH",
    "EVIDENCE_ID_MISMATCH",
    "ORPHAN_RECORD",
    "CONFLICT",
    "TAMPERED",
    "FAILED_CLOSED",
)
_RAW_MARKERS = (
    "raw_payload",
    "raw_evidence",
    "raw_approval",
    "approval_content",
    "payload_body",
    "secret",
    "token",
    "credential",
    "credentials",
    "private_key",
    "certificate_body",
)
_EXECUTION_FLAGS = (
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "runtime_execution",
    "deployment_execution",
    "policy_mutation",
    "network_access",
)


@dataclass(frozen=True)
class RegistryAppendContext:
    expected_previous_hash: str = REGISTRY_GENESIS_HASH


@dataclass(frozen=True)
class RegistryAppendResult:
    status: str
    errors: tuple[str, ...]
    registry_record_hash: str
    previous_registry_hash: str
    registry_position: int
    written: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "errors": list(self.errors),
            "registry_record_hash": self.registry_record_hash,
            "previous_registry_hash": self.previous_registry_hash,
            "registry_position": self.registry_position,
            "written": self.written,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class CrossRegistryVerificationReport:
    result: str
    failure_code: str
    verification_report_id: str
    correlation_id: str
    tenant: str
    policy_version: str
    evidence_id: str
    audit_record_hash: str
    ledger_record_hash: str
    attestation_hash: str
    export_manifest_hash: str
    audit_registry_position: int
    ledger_registry_position: int
    attestation_registry_position: int
    export_registry_position: int
    generated_at: str
    report_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": CROSS_REGISTRY_REPORT_SCHEMA,
            "result": self.result,
            "failure_code": self.failure_code,
            "verification_report_id": self.verification_report_id,
            "correlation_id": self.correlation_id,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "evidence_id": self.evidence_id,
            "audit_record_hash": self.audit_record_hash,
            "ledger_record_hash": self.ledger_record_hash,
            "attestation_hash": self.attestation_hash,
            "export_manifest_hash": self.export_manifest_hash,
            "audit_registry_position": self.audit_registry_position,
            "ledger_registry_position": self.ledger_registry_position,
            "attestation_registry_position": self.attestation_registry_position,
            "export_registry_position": self.export_registry_position,
            "generated_at": self.generated_at,
            "report_hash": self.report_hash,
            **_false_execution_flags(),
        }


def attestation_export_registry_schema() -> dict[str, Any]:
    return {
        "schema": ATTESTATION_EXPORT_REGISTRY_SCHEMA,
        "attestation_record_schema": ATTESTATION_REGISTRY_RECORD_SCHEMA,
        "export_bundle_record_schema": EXPORT_BUNDLE_REGISTRY_RECORD_SCHEMA,
        "cross_registry_report_schema": CROSS_REGISTRY_REPORT_SCHEMA,
        "statuses": list(REGISTRY_STATUSES),
        "cross_registry_states": list(CROSS_REGISTRY_STATES),
        "payload_policy": "hash-only",
        "storage": "local-jsonl-append-only",
        **_false_execution_flags(),
    }


def build_attestation_registry_record(
    attestation: dict[str, Any],
    *,
    reconciliation: dict[str, Any],
    audit_record: dict[str, Any],
    ledger_record: dict[str, Any],
    previous_registry_hash: str = REGISTRY_GENESIS_HASH,
    position: int = 0,
) -> dict[str, Any]:
    errors = _attestation_gate(attestation, reconciliation, audit_record, ledger_record)
    if errors:
        raise ValueError(errors[0])
    _validate_hash(previous_registry_hash)
    payload = {
        "schema": ATTESTATION_REGISTRY_RECORD_SCHEMA,
        "registry_record_id": "",
        "record_type": "reconciliation_attestation",
        "position": position,
        "attestation_id": attestation["attestation_id"],
        "reconciliation_id": attestation["reconciliation_id"],
        "correlation_id": attestation["correlation_id"],
        "tenant": attestation["tenant"],
        "policy_version": attestation["policy_version"],
        "evidence_id": attestation["evidence_id"],
        "governance_decision": attestation["governance_decision"],
        "failure_code": attestation["failure_code"],
        "attestation_hash": attestation["attestation_hash"],
        "reconciliation_report_hash": attestation["reconciliation_report_hash"],
        "audit_record_hash": attestation["audit_record_hash"],
        "runtime_ledger_record_hash": attestation["runtime_ledger_record_hash"],
        "audit_chain_reference": attestation["audit_chain_reference"],
        "ledger_chain_reference": attestation["ledger_chain_reference"],
        "canonical_payload_hash": attestation["canonical_payload_hash"],
        "issued_at": attestation["issued_at"],
        "attestation_version": attestation["attestation_version"],
        "previous_registry_hash": previous_registry_hash,
        **_false_execution_flags(),
    }
    payload["registry_record_id"] = sha256_audit_hash(
        {
            key: value
            for key, value in payload.items()
            if key not in {"registry_record_id", "issued_at", "position", "previous_registry_hash"}
        }
    )
    record = {**payload, "registry_record_hash": sha256_audit_hash(payload)}
    _assert_safe(record)
    return record


def build_export_bundle_registry_record(
    bundle: dict[str, Any],
    *,
    attestation_record: dict[str, Any],
    attestation: dict[str, Any],
    audit_record: dict[str, Any],
    ledger_record: dict[str, Any],
    previous_registry_hash: str = REGISTRY_GENESIS_HASH,
    position: int = 0,
) -> dict[str, Any]:
    errors = _export_gate(bundle, attestation_record, attestation, audit_record, ledger_record)
    if errors:
        raise ValueError(errors[0])
    _validate_hash(previous_registry_hash)
    payload = {
        "schema": EXPORT_BUNDLE_REGISTRY_RECORD_SCHEMA,
        "registry_record_id": "",
        "record_type": "regulator_export_bundle",
        "position": position,
        "export_bundle_id": bundle["export_bundle_id"],
        "export_profile": bundle["export_profile"],
        "jurisdiction_reference": bundle["jurisdiction_reference"],
        "tenant": bundle["tenant"],
        "policy_version": bundle["policy_version"],
        "evidence_id": bundle["evidence_id"],
        "reconciliation_attestation_reference": bundle["reconciliation_attestation_reference"],
        "attestation_hash": attestation["attestation_hash"],
        "bundle_manifest_hash": bundle["bundle_manifest_hash"],
        "audit_record_reference": bundle["audit_record_reference"],
        "runtime_ledger_reference": bundle["runtime_ledger_reference"],
        "audit_chain_reference": bundle["audit_chain_reference"],
        "ledger_chain_reference": bundle["ledger_chain_reference"],
        "signed_auditor_bundle_reference": bundle.get("signed_auditor_bundle_reference") or None,
        "sealed_archive_reference": bundle.get("sealed_archive_reference") or None,
        "worm_reference": bundle.get("worm_reference") or None,
        "timestamp_reference": bundle.get("timestamp_reference") or None,
        "generated_at": bundle["generated_at"],
        "bundle_version": bundle["bundle_version"],
        "previous_registry_hash": previous_registry_hash,
        **_false_execution_flags(),
    }
    payload["registry_record_id"] = sha256_audit_hash(
        {
            key: value
            for key, value in payload.items()
            if key not in {"registry_record_id", "generated_at", "position", "previous_registry_hash"}
        }
    )
    record = {**payload, "registry_record_hash": sha256_audit_hash(payload)}
    _assert_safe(record)
    return record


def append_attestation_registry_record(
    storage_path: Path,
    attestation: dict[str, Any],
    *,
    reconciliation: dict[str, Any],
    audit_record: dict[str, Any],
    ledger_record: dict[str, Any],
    context: RegistryAppendContext = RegistryAppendContext(),
) -> RegistryAppendResult:
    return _append_record(
        storage_path,
        "attestation",
        context,
        lambda previous_hash, position: build_attestation_registry_record(
            attestation,
            reconciliation=reconciliation,
            audit_record=audit_record,
            ledger_record=ledger_record,
            previous_registry_hash=previous_hash,
            position=position,
        ),
    )


def append_export_bundle_registry_record(
    storage_path: Path,
    bundle: dict[str, Any],
    *,
    attestation_record: dict[str, Any],
    attestation: dict[str, Any],
    audit_record: dict[str, Any],
    ledger_record: dict[str, Any],
    context: RegistryAppendContext = RegistryAppendContext(),
) -> RegistryAppendResult:
    return _append_record(
        storage_path,
        "export",
        context,
        lambda previous_hash, position: build_export_bundle_registry_record(
            bundle,
            attestation_record=attestation_record,
            attestation=attestation,
            audit_record=audit_record,
            ledger_record=ledger_record,
            previous_registry_hash=previous_hash,
            position=position,
        ),
    )


def load_registry_records(storage_path: Path) -> tuple[dict[str, Any], ...]:
    _validate_storage_path(storage_path)
    if not storage_path.exists():
        return ()
    try:
        records = []
        for line in storage_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                raise ValueError("MALFORMED_RECORD")
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("MALFORMED_RECORD")
            records.append(payload)
        return tuple(records)
    except json.JSONDecodeError as exc:
        raise ValueError("MALFORMED_RECORD") from exc
    except OSError as exc:
        raise ValueError("FAILED_CLOSED") from exc


def verify_registry_records(records: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> tuple[str, ...]:
    if not isinstance(records, (tuple, list)):
        return ("MALFORMED_RECORD",)
    errors: list[str] = []
    previous = REGISTRY_GENESIS_HASH
    seen_ids: dict[str, dict[str, Any]] = {}
    seen_attestations: dict[str, dict[str, Any]] = {}
    seen_exports: dict[str, dict[str, Any]] = {}
    for position, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append("MALFORMED_RECORD")
            continue
        try:
            _assert_safe(record)
        except ValueError:
            errors.append("SERIALIZATION_FAILURE")
        if record.get("position") != position:
            errors.append("REGISTRY_REORDERED")
        if record.get("previous_registry_hash") != previous:
            errors.append("CHAIN_INVALID")
        if record.get("schema") not in {ATTESTATION_REGISTRY_RECORD_SCHEMA, EXPORT_BUNDLE_REGISTRY_RECORD_SCHEMA}:
            errors.append("MALFORMED_RECORD")
        if record.get("registry_record_hash") != sha256_audit_hash({key: value for key, value in record.items() if key != "registry_record_hash"}):
            errors.append("REGISTRY_TAMPERED")
        if any(record.get(flag) is not False for flag in _EXECUTION_FLAGS):
            errors.append("FAILED_CLOSED")
        for field in _required_fields(record):
            if record.get(field) in ("", None):
                errors.append("MALFORMED_RECORD")
        registry_id = str(record.get("registry_record_id", ""))
        if registry_id in seen_ids:
            errors.append("DUPLICATE_RECORD" if seen_ids[registry_id] == record else "RECORD_CONFLICT")
        seen_ids[registry_id] = dict(record)
        if record.get("schema") == ATTESTATION_REGISTRY_RECORD_SCHEMA:
            _duplicate_by("attestation_id", record, seen_attestations, errors)
            _duplicate_by("reconciliation_id", record, seen_attestations, errors)
            _duplicate_by("correlation_id", record, seen_attestations, errors)
        elif record.get("schema") == EXPORT_BUNDLE_REGISTRY_RECORD_SCHEMA:
            _duplicate_by("export_bundle_id", record, seen_exports, errors)
            _duplicate_by("bundle_manifest_hash", record, seen_exports, errors)
        previous = str(record.get("registry_record_hash", ""))
    return _ordered_unique(errors, REGISTRY_STATUSES)


def build_cross_registry_report(
    *,
    audit_record: dict[str, Any] | None,
    ledger_record: dict[str, Any] | None,
    attestation_record: dict[str, Any] | None,
    export_record: dict[str, Any] | None,
    generated_at: str,
) -> CrossRegistryVerificationReport:
    errors: list[str] = []
    if audit_record is None:
        errors.append("AUDIT_RECORD_MISSING")
        audit_record = {}
    if ledger_record is None:
        errors.append("LEDGER_RECORD_MISSING")
        ledger_record = {}
    if attestation_record is None:
        errors.append("ATTESTATION_MISSING")
        attestation_record = {}
    if export_record is None:
        errors.append("EXPORT_RECORD_MISSING")
        export_record = {}
    for record in (attestation_record, export_record):
        if record and _record_integrity_errors(record):
            errors.append("TAMPERED")
    for field, code in (
        ("correlation_id", "REFERENCE_MISMATCH"),
        ("tenant", "TENANT_MISMATCH"),
        ("policy_version", "POLICY_VERSION_MISMATCH"),
        ("evidence_id", "EVIDENCE_ID_MISMATCH"),
    ):
        values = {
            str(record.get(field, ""))
            for record in (audit_record, ledger_record, attestation_record, export_record)
            if record and record.get(field) not in ("", None)
        }
        if len(values) > 1:
            errors.append(code)
    if attestation_record:
        if audit_record and attestation_record.get("audit_record_hash") != audit_record.get("record_hash"):
            errors.append("HASH_MISMATCH")
        if ledger_record and attestation_record.get("runtime_ledger_record_hash") != ledger_record.get("record_hash"):
            errors.append("HASH_MISMATCH")
    if export_record:
        if attestation_record and export_record.get("attestation_hash") != attestation_record.get("attestation_hash"):
            errors.append("REFERENCE_MISMATCH")
        if audit_record and export_record.get("audit_record_reference") != audit_record.get("record_hash"):
            errors.append("HASH_MISMATCH")
        if ledger_record and export_record.get("runtime_ledger_reference") != ledger_record.get("record_hash"):
            errors.append("HASH_MISMATCH")
    result = "CONSISTENT" if not errors else _ordered_unique(errors, CROSS_REGISTRY_STATES)[0]
    payload = {
        "schema": CROSS_REGISTRY_REPORT_SCHEMA,
        "result": result,
        "failure_code": "" if result == "CONSISTENT" else result,
        "correlation_id": _first("correlation_id", audit_record, ledger_record, attestation_record, export_record),
        "tenant": _first("tenant", audit_record, ledger_record, attestation_record, export_record),
        "policy_version": _first("policy_version", audit_record, ledger_record, attestation_record, export_record),
        "evidence_id": _first("evidence_id", audit_record, ledger_record, attestation_record, export_record),
        "audit_record_hash": str(audit_record.get("record_hash", "")),
        "ledger_record_hash": str(ledger_record.get("record_hash", "")),
        "attestation_hash": str(attestation_record.get("attestation_hash", "")),
        "export_manifest_hash": str(export_record.get("bundle_manifest_hash", "")),
        "audit_registry_position": int(audit_record.get("position", -1)) if str(audit_record.get("position", "")).lstrip("-").isdigit() else -1,
        "ledger_registry_position": int(ledger_record.get("position", -1)) if str(ledger_record.get("position", "")).lstrip("-").isdigit() else -1,
        "attestation_registry_position": int(attestation_record.get("position", -1)) if str(attestation_record.get("position", "")).lstrip("-").isdigit() else -1,
        "export_registry_position": int(export_record.get("position", -1)) if str(export_record.get("position", "")).lstrip("-").isdigit() else -1,
        "generated_at": generated_at,
        **_false_execution_flags(),
    }
    report_id = sha256_audit_hash({key: value for key, value in payload.items() if key != "generated_at"})
    final = {**payload, "verification_report_id": report_id}
    return CrossRegistryVerificationReport(
        result=payload["result"],
        failure_code=payload["failure_code"],
        verification_report_id=report_id,
        correlation_id=payload["correlation_id"],
        tenant=payload["tenant"],
        policy_version=payload["policy_version"],
        evidence_id=payload["evidence_id"],
        audit_record_hash=payload["audit_record_hash"],
        ledger_record_hash=payload["ledger_record_hash"],
        attestation_hash=payload["attestation_hash"],
        export_manifest_hash=payload["export_manifest_hash"],
        audit_registry_position=payload["audit_registry_position"],
        ledger_registry_position=payload["ledger_registry_position"],
        attestation_registry_position=payload["attestation_registry_position"],
        export_registry_position=payload["export_registry_position"],
        generated_at=generated_at,
        report_hash=sha256_audit_hash(final),
    )


def _append_record(storage_path: Path, kind: str, context: RegistryAppendContext, builder: Any) -> RegistryAppendResult:
    try:
        _validate_storage_path(storage_path)
        lock_fd = _acquire_lock(storage_path.with_suffix(storage_path.suffix + ".lock"))
    except ValueError as exc:
        return _blocked(str(exc))
    lock_path = storage_path.with_suffix(storage_path.suffix + ".lock")
    try:
        records = load_registry_records(storage_path)
        verification = verify_registry_records(records)
        if verification:
            return _blocked(verification[0])
        expected_previous = records[-1]["registry_record_hash"] if records else REGISTRY_GENESIS_HASH
        if context.expected_previous_hash != expected_previous:
            return _blocked("CHAIN_INVALID")
        record = builder(context.expected_previous_hash, len(records))
        duplicate = _registry_duplicate(records, record, kind)
        if duplicate is not None:
            return duplicate
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        with storage_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_audit_json(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return _result("PERSISTED", (), record, True)
    except (OSError, ValueError) as exc:
        return _blocked(str(exc))
    finally:
        _release_lock(lock_fd, lock_path)


def _registry_duplicate(records: tuple[dict[str, Any], ...], record: dict[str, Any], kind: str) -> RegistryAppendResult | None:
    key = "attestation_id" if kind == "attestation" else "export_bundle_id"
    for existing in records:
        if existing.get(key) == record.get(key):
            if _logical_record_match(existing, record):
                return _result("ALREADY_PERSISTED", (), existing, False)
            return _result("FAILED_CLOSED", ("RECORD_CONFLICT",), record, False)
    return None


def _attestation_gate(attestation: dict[str, Any], reconciliation: dict[str, Any], audit_record: dict[str, Any], ledger_record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(attestation, dict):
        errors.append("ATTESTATION_REQUIRED")
    elif verify_reconciliation_attestation(attestation, reconciliation=reconciliation, audit_record=audit_record, ledger_record=ledger_record):
        errors.append("ATTESTATION_INVALID")
    if not isinstance(audit_record, dict):
        errors.append("ORPHAN_REFERENCE")
    if not isinstance(ledger_record, dict):
        errors.append("ORPHAN_REFERENCE")
    return _ordered_unique(errors, REGISTRY_STATUSES)


def _export_gate(bundle: dict[str, Any], attestation_record: dict[str, Any], attestation: dict[str, Any], audit_record: dict[str, Any], ledger_record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(attestation_record, dict) or attestation_record.get("schema") != ATTESTATION_REGISTRY_RECORD_SCHEMA:
        errors.append("ORPHAN_REFERENCE")
    if not isinstance(bundle, dict):
        errors.append("EXPORT_BUNDLE_INVALID")
    elif verify_regulator_export_bundle(bundle, attestation=attestation, audit_record=audit_record, ledger_record=ledger_record):
        errors.append("EXPORT_BUNDLE_INVALID")
    if attestation_record and bundle and bundle.get("reconciliation_attestation_reference") != attestation_record.get("attestation_hash"):
        errors.append("REFERENCE_MISMATCH")
    return _ordered_unique(errors, REGISTRY_STATUSES)


def _duplicate_by(field: str, record: dict[str, Any], seen: dict[str, dict[str, Any]], errors: list[str]) -> None:
    key = str(record.get(field, ""))
    if not key:
        return
    if key in seen:
        errors.append("DUPLICATE_RECORD" if _logical_record_match(seen[key], record) else "RECORD_CONFLICT")
    seen[key] = dict(record)


def _record_integrity_errors(record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        _assert_safe(record)
    except ValueError:
        errors.append("SERIALIZATION_FAILURE")
    if record.get("schema") not in {ATTESTATION_REGISTRY_RECORD_SCHEMA, EXPORT_BUNDLE_REGISTRY_RECORD_SCHEMA}:
        errors.append("MALFORMED_RECORD")
    if record.get("registry_record_hash") != sha256_audit_hash({key: value for key, value in record.items() if key != "registry_record_hash"}):
        errors.append("REGISTRY_TAMPERED")
    if any(record.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("FAILED_CLOSED")
    for field in _required_fields(record):
        if record.get(field) in ("", None):
            errors.append("MALFORMED_RECORD")
    return _ordered_unique(errors, REGISTRY_STATUSES)


def _logical_record_match(left: dict[str, Any], right: dict[str, Any]) -> bool:
    volatile = {"position", "previous_registry_hash", "registry_record_hash"}
    return {key: value for key, value in left.items() if key not in volatile} == {
        key: value for key, value in right.items() if key not in volatile
    }


def _required_fields(record: dict[str, Any]) -> tuple[str, ...]:
    if record.get("schema") == ATTESTATION_REGISTRY_RECORD_SCHEMA:
        return (
            "registry_record_id",
            "attestation_id",
            "reconciliation_id",
            "correlation_id",
            "tenant",
            "policy_version",
            "evidence_id",
            "attestation_hash",
            "reconciliation_report_hash",
            "audit_record_hash",
            "runtime_ledger_record_hash",
            "previous_registry_hash",
            "registry_record_hash",
        )
    return (
        "registry_record_id",
        "export_bundle_id",
        "export_profile",
        "jurisdiction_reference",
        "tenant",
        "policy_version",
        "evidence_id",
        "reconciliation_attestation_reference",
        "attestation_hash",
        "bundle_manifest_hash",
        "audit_record_reference",
        "runtime_ledger_reference",
        "previous_registry_hash",
        "registry_record_hash",
    )


def _result(status: str, errors: tuple[str, ...], record: dict[str, Any], written: bool) -> RegistryAppendResult:
    return RegistryAppendResult(
        status=status,
        errors=errors,
        registry_record_hash=str(record.get("registry_record_hash", "")),
        previous_registry_hash=str(record.get("previous_registry_hash", "")),
        registry_position=int(record.get("position", -1)),
        written=written,
    )


def _blocked(error: str) -> RegistryAppendResult:
    status = "LOCKED" if error == "LOCKED" else "FAILED_CLOSED"
    return RegistryAppendResult(status=status, errors=(error,), registry_record_hash="", previous_registry_hash="", registry_position=-1, written=False)


def _validate_storage_path(path: Path) -> None:
    if not isinstance(path, Path) or path.name in {"", ".", ".."}:
        raise ValueError("MALFORMED_RECORD")


def _acquire_lock(lock_path: Path) -> int:
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        return os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise ValueError("LOCKED") from exc
    except OSError as exc:
        raise ValueError("FAILED_CLOSED") from exc


def _release_lock(lock_fd: int | None, lock_path: Path) -> None:
    if lock_fd is not None:
        os.close(lock_fd)
    try:
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass


def _validate_hash(value: str) -> None:
    if not _is_sha256_reference(value):
        raise ValueError("HASH_MISMATCH")


def _is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _ordered_unique(errors: list[str], order: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(code for code in order if code in errors)


def _first(field: str, *records: dict[str, Any]) -> str:
    for record in records:
        value = record.get(field, "") if isinstance(record, dict) else ""
        if value not in ("", None):
            return str(value)
    return ""


def _false_execution_flags() -> dict[str, bool]:
    return {flag: False for flag in _EXECUTION_FLAGS}


def _assert_safe(record: Any) -> None:
    serialized = canonical_audit_json(record)
    lowered = serialized.lower()
    if any(marker in lowered for marker in _RAW_MARKERS):
        raise ValueError("SERIALIZATION_FAILURE")
