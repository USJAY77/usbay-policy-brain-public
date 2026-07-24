from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.audit_evidence import canonical_audit_json, sha256_audit_hash
from governance.audit_evidence_persistence import verify_pipeline_persistence_records
from governance.runtime_ledger_persistence import (
    RuntimeLedgerReconciliationResult,
    verify_runtime_ledger_persistence_records,
)


RECONCILIATION_ATTESTATION_SCHEMA = "usbay.governance.reconciliation_attestation.v1"
RECONCILIATION_EXPORT_BUNDLE_SCHEMA = RECONCILIATION_ATTESTATION_SCHEMA + ".regulator_export_bundle"
RECONCILIATION_SIGNING_INPUT_SCHEMA = RECONCILIATION_ATTESTATION_SCHEMA + ".signing_input"
ATTESTATION_VERSION = "reconciliation-attestation-v1"
EXPORT_BUNDLE_VERSION = "reconciliation-export-bundle-v1"
ATTESTATION_RESULT_STATES = (
    "ATTESTATION_VALID",
    "RECONCILIATION_REQUIRED",
    "RECONCILIATION_INVALID",
    "AUDIT_REFERENCE_MISSING",
    "LEDGER_REFERENCE_MISSING",
    "HASH_MISMATCH",
    "TENANT_MISMATCH",
    "POLICY_VERSION_MISMATCH",
    "EVIDENCE_ID_MISMATCH",
    "DECISION_MISMATCH",
    "FAILURE_CODE_MISMATCH",
    "CHAIN_REFERENCE_INVALID",
    "DUPLICATE_ATTESTATION",
    "ATTESTATION_CONFLICT",
    "MALFORMED_CONTEXT",
    "SERIALIZATION_FAILURE",
    "FAILED_CLOSED",
)
EXPORT_RESULT_STATES = (
    "EXPORT_BUNDLE_VALID",
    "ATTESTATION_REQUIRED",
    "ATTESTATION_INVALID",
    "AUDIT_REFERENCE_MISSING",
    "LEDGER_REFERENCE_MISSING",
    "HASH_MISMATCH",
    "TENANT_MISMATCH",
    "POLICY_VERSION_MISMATCH",
    "EVIDENCE_ID_MISMATCH",
    "DECISION_MISMATCH",
    "FAILURE_CODE_MISMATCH",
    "CHAIN_REFERENCE_INVALID",
    "DUPLICATE_ATTESTATION",
    "ATTESTATION_CONFLICT",
    "MALFORMED_CONTEXT",
    "SERIALIZATION_FAILURE",
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
    "prompt",
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
class ReconciliationAttestationContext:
    issued_at: str
    audit_chain_reference: str
    ledger_chain_reference: str
    attestation_version: str = ATTESTATION_VERSION


@dataclass(frozen=True)
class RegulatorExportBundleContext:
    export_profile: str
    jurisdiction_reference: str
    generated_at: str
    signed_auditor_bundle_reference: str = ""
    sealed_archive_reference: str = ""
    worm_reference: str = ""
    timestamp_reference: str = ""
    bundle_version: str = EXPORT_BUNDLE_VERSION


@dataclass(frozen=True)
class AttestationBuildResult:
    result: str
    errors: tuple[str, ...]
    attestation: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "errors": list(self.errors),
            "attestation": self.attestation,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class ExportBundleBuildResult:
    result: str
    errors: tuple[str, ...]
    bundle: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "errors": list(self.errors),
            "bundle": self.bundle,
            **_false_execution_flags(),
        }


def reconciliation_attestation_schema() -> dict[str, Any]:
    return {
        "schema": RECONCILIATION_ATTESTATION_SCHEMA,
        "export_bundle_schema": RECONCILIATION_EXPORT_BUNDLE_SCHEMA,
        "signing_input_schema": RECONCILIATION_SIGNING_INPUT_SCHEMA,
        "attestation_result_states": list(ATTESTATION_RESULT_STATES),
        "export_result_states": list(EXPORT_RESULT_STATES),
        "payload_policy": "hash-only",
        **_false_execution_flags(),
    }


def build_reconciliation_attestation(
    *,
    reconciliation: RuntimeLedgerReconciliationResult | dict[str, Any] | None,
    audit_record: dict[str, Any] | None,
    ledger_record: dict[str, Any] | None,
    context: ReconciliationAttestationContext,
) -> AttestationBuildResult:
    errors = _attestation_errors(reconciliation, audit_record, ledger_record, context)
    if errors:
        return AttestationBuildResult(errors[0], errors, None)
    reconciliation_payload = _payload(reconciliation)
    assert audit_record is not None
    assert ledger_record is not None
    payload = {
        "schema": RECONCILIATION_ATTESTATION_SCHEMA,
        "attestation_id": "",
        "reconciliation_id": reconciliation_payload["reconciliation_id"],
        "correlation_id": reconciliation_payload["correlation_id"],
        "tenant": reconciliation_payload["tenant"],
        "policy_version": reconciliation_payload["policy_version"],
        "evidence_id": reconciliation_payload["evidence_id"],
        "governance_decision": ledger_record["governance_decision"],
        "failure_code": ledger_record["failure_code"],
        "audit_record_hash": audit_record["record_hash"],
        "runtime_ledger_record_hash": ledger_record["record_hash"],
        "runtime_ledger_entry_hash": ledger_record["ledger_entry_hash"],
        "reconciliation_report_hash": reconciliation_payload["report_hash"],
        "audit_chain_reference": context.audit_chain_reference,
        "ledger_chain_reference": context.ledger_chain_reference,
        "validator_sequence_hash": audit_record["validator_sequence_hash"],
        "canonical_payload_hash": audit_record["canonical_payload_hash"],
        "issued_at": context.issued_at,
        "attestation_version": context.attestation_version,
        **_false_execution_flags(),
    }
    payload["attestation_id"] = sha256_audit_hash({key: value for key, value in payload.items() if key not in {"attestation_id", "issued_at"}})
    attestation = {**payload, "attestation_hash": sha256_audit_hash(payload)}
    if _has_raw_marker(attestation):
        return AttestationBuildResult("SERIALIZATION_FAILURE", ("SERIALIZATION_FAILURE",), None)
    return AttestationBuildResult("ATTESTATION_VALID", (), attestation)


def verify_reconciliation_attestation(
    attestation: dict[str, Any] | None,
    *,
    reconciliation: RuntimeLedgerReconciliationResult | dict[str, Any] | None,
    audit_record: dict[str, Any] | None,
    ledger_record: dict[str, Any] | None,
) -> tuple[str, ...]:
    if not isinstance(attestation, dict):
        return ("RECONCILIATION_REQUIRED",)
    errors: list[str] = []
    if attestation.get("schema") != RECONCILIATION_ATTESTATION_SCHEMA:
        errors.append("RECONCILIATION_INVALID")
    if _has_raw_marker(attestation):
        errors.append("SERIALIZATION_FAILURE")
    if any(attestation.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("FAILED_CLOSED")
    reconciliation_payload = _payload(reconciliation)
    if reconciliation_payload.get("result") not in {"CONSISTENT", "ALREADY_RECONCILED"}:
        errors.append("RECONCILIATION_INVALID")
    if not isinstance(audit_record, dict):
        errors.append("AUDIT_REFERENCE_MISSING")
        audit_record = {}
    if not isinstance(ledger_record, dict):
        errors.append("LEDGER_REFERENCE_MISSING")
        ledger_record = {}
    for field, code in (
        ("reconciliation_id", "RECONCILIATION_INVALID"),
        ("correlation_id", "HASH_MISMATCH"),
        ("tenant", "TENANT_MISMATCH"),
        ("policy_version", "POLICY_VERSION_MISMATCH"),
        ("evidence_id", "EVIDENCE_ID_MISMATCH"),
    ):
        if reconciliation_payload.get(field) and attestation.get(field) != reconciliation_payload.get(field):
            errors.append(code)
    if audit_record:
        if attestation.get("audit_record_hash") != audit_record.get("record_hash"):
            errors.append("AUDIT_REFERENCE_MISSING")
        if attestation.get("canonical_payload_hash") != audit_record.get("canonical_payload_hash"):
            errors.append("HASH_MISMATCH")
        if attestation.get("validator_sequence_hash") != audit_record.get("validator_sequence_hash"):
            errors.append("HASH_MISMATCH")
    if ledger_record:
        if attestation.get("runtime_ledger_record_hash") != ledger_record.get("record_hash"):
            errors.append("LEDGER_REFERENCE_MISSING")
        if attestation.get("runtime_ledger_entry_hash") != ledger_record.get("ledger_entry_hash"):
            errors.append("LEDGER_REFERENCE_MISSING")
        if attestation.get("governance_decision") != ledger_record.get("governance_decision"):
            errors.append("DECISION_MISMATCH")
        if attestation.get("failure_code") != ledger_record.get("failure_code"):
            errors.append("FAILURE_CODE_MISMATCH")
    if not _is_sha256_reference(attestation.get("audit_chain_reference")) or not _is_sha256_reference(attestation.get("ledger_chain_reference")):
        errors.append("CHAIN_REFERENCE_INVALID")
    expected_id = sha256_audit_hash({key: value for key, value in attestation.items() if key not in {"attestation_id", "attestation_hash", "issued_at"}})
    expected_hash = sha256_audit_hash({key: value for key, value in attestation.items() if key != "attestation_hash"})
    if attestation.get("attestation_id") != expected_id or attestation.get("attestation_hash") != expected_hash:
        errors.append("HASH_MISMATCH")
    return _ordered_unique(errors, ATTESTATION_RESULT_STATES)


def build_regulator_export_bundle(
    *,
    attestation: dict[str, Any] | None,
    audit_record: dict[str, Any] | None,
    ledger_record: dict[str, Any] | None,
    context: RegulatorExportBundleContext,
) -> ExportBundleBuildResult:
    errors = _export_errors(attestation, audit_record, ledger_record, context)
    if errors:
        return ExportBundleBuildResult(errors[0], errors, None)
    assert attestation is not None
    assert audit_record is not None
    assert ledger_record is not None
    manifest = {
        "reconciliation_attestation_hash": attestation["attestation_hash"],
        "audit_record_hash": audit_record["record_hash"],
        "runtime_ledger_record_hash": ledger_record["record_hash"],
        "audit_chain_reference": attestation["audit_chain_reference"],
        "ledger_chain_reference": attestation["ledger_chain_reference"],
        "signed_auditor_bundle_reference": context.signed_auditor_bundle_reference,
        "sealed_archive_reference": context.sealed_archive_reference,
        "worm_reference": context.worm_reference,
        "timestamp_reference": context.timestamp_reference,
    }
    payload = {
        "schema": RECONCILIATION_EXPORT_BUNDLE_SCHEMA,
        "export_bundle_id": "",
        "export_profile": context.export_profile,
        "jurisdiction_reference": context.jurisdiction_reference,
        "tenant": attestation["tenant"],
        "policy_version": attestation["policy_version"],
        "evidence_id": attestation["evidence_id"],
        "reconciliation_attestation_reference": attestation["attestation_hash"],
        "audit_record_reference": audit_record["record_hash"],
        "runtime_ledger_reference": ledger_record["record_hash"],
        "audit_chain_reference": attestation["audit_chain_reference"],
        "ledger_chain_reference": attestation["ledger_chain_reference"],
        "signed_auditor_bundle_reference": context.signed_auditor_bundle_reference,
        "sealed_archive_reference": context.sealed_archive_reference,
        "worm_reference": context.worm_reference,
        "timestamp_reference": context.timestamp_reference,
        "generated_at": context.generated_at,
        "bundle_version": context.bundle_version,
        "bundle_manifest_hash": sha256_audit_hash(manifest),
        **_false_execution_flags(),
    }
    payload["export_bundle_id"] = sha256_audit_hash({key: value for key, value in payload.items() if key not in {"export_bundle_id", "generated_at"}})
    bundle = {**payload, "bundle_hash": sha256_audit_hash(payload)}
    if _has_raw_marker(bundle):
        return ExportBundleBuildResult("SERIALIZATION_FAILURE", ("SERIALIZATION_FAILURE",), None)
    return ExportBundleBuildResult("EXPORT_BUNDLE_VALID", (), bundle)


def verify_regulator_export_bundle(
    bundle: dict[str, Any] | None,
    *,
    attestation: dict[str, Any] | None,
    audit_record: dict[str, Any] | None,
    ledger_record: dict[str, Any] | None,
) -> tuple[str, ...]:
    if not isinstance(bundle, dict):
        return ("ATTESTATION_REQUIRED",)
    errors: list[str] = []
    if bundle.get("schema") != RECONCILIATION_EXPORT_BUNDLE_SCHEMA:
        errors.append("ATTESTATION_INVALID")
    if _has_raw_marker(bundle):
        errors.append("SERIALIZATION_FAILURE")
    if any(bundle.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("FAILED_CLOSED")
    if not isinstance(attestation, dict):
        errors.append("ATTESTATION_REQUIRED")
        attestation = {}
    if not isinstance(audit_record, dict):
        errors.append("AUDIT_REFERENCE_MISSING")
        audit_record = {}
    if not isinstance(ledger_record, dict):
        errors.append("LEDGER_REFERENCE_MISSING")
        ledger_record = {}
    if attestation:
        if bundle.get("reconciliation_attestation_reference") != attestation.get("attestation_hash"):
            errors.append("HASH_MISMATCH")
        for field, code in (("tenant", "TENANT_MISMATCH"), ("policy_version", "POLICY_VERSION_MISMATCH"), ("evidence_id", "EVIDENCE_ID_MISMATCH")):
            if bundle.get(field) != attestation.get(field):
                errors.append(code)
    if audit_record and bundle.get("audit_record_reference") != audit_record.get("record_hash"):
        errors.append("AUDIT_REFERENCE_MISSING")
    if ledger_record and bundle.get("runtime_ledger_reference") != ledger_record.get("record_hash"):
        errors.append("LEDGER_REFERENCE_MISSING")
    expected_id = sha256_audit_hash({key: value for key, value in bundle.items() if key not in {"export_bundle_id", "bundle_hash", "generated_at"}})
    expected_hash = sha256_audit_hash({key: value for key, value in bundle.items() if key != "bundle_hash"})
    if bundle.get("export_bundle_id") != expected_id or bundle.get("bundle_hash") != expected_hash:
        errors.append("HASH_MISMATCH")
    return _ordered_unique(errors, EXPORT_RESULT_STATES)


def build_signed_bundle_input(bundle: dict[str, Any], attestation: dict[str, Any]) -> dict[str, Any]:
    errors = verify_regulator_export_bundle(bundle, attestation=attestation, audit_record={"record_hash": bundle.get("audit_record_reference")}, ledger_record={"record_hash": bundle.get("runtime_ledger_reference")})
    if errors:
        raise ValueError(errors[0])
    payload = {
        "schema": RECONCILIATION_SIGNING_INPUT_SCHEMA,
        "reconciliation_attestation_hash": attestation["attestation_hash"],
        "regulator_export_bundle_manifest_hash": bundle["bundle_manifest_hash"],
        "audit_record_hash": bundle["audit_record_reference"],
        "runtime_ledger_record_hash": bundle["runtime_ledger_reference"],
        "audit_chain_reference": bundle["audit_chain_reference"],
        "ledger_chain_reference": bundle["ledger_chain_reference"],
        "tenant": bundle["tenant"],
        "policy_version": bundle["policy_version"],
        "evidence_id": bundle["evidence_id"],
        **_false_execution_flags(),
    }
    return {**payload, "signing_input_hash": sha256_audit_hash(payload)}


def verify_unique_attestations(attestations: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> tuple[str, ...]:
    seen: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for attestation in attestations:
        if not isinstance(attestation, dict) or attestation.get("attestation_hash") == "":
            errors.append("RECONCILIATION_INVALID")
            continue
        reconciliation_id = str(attestation.get("reconciliation_id", ""))
        if reconciliation_id in seen:
            if seen[reconciliation_id] == attestation:
                errors.append("DUPLICATE_ATTESTATION")
            else:
                errors.append("ATTESTATION_CONFLICT")
        seen[reconciliation_id] = dict(attestation)
    return _ordered_unique(errors, ATTESTATION_RESULT_STATES)


def verify_unique_export_bundles(bundles: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> tuple[str, ...]:
    seen: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for bundle in bundles:
        if not isinstance(bundle, dict) or bundle.get("bundle_hash") == "":
            errors.append("ATTESTATION_INVALID")
            continue
        key = str(bundle.get("reconciliation_attestation_reference", ""))
        if key in seen:
            if seen[key] == bundle:
                errors.append("DUPLICATE_ATTESTATION")
            else:
                errors.append("ATTESTATION_CONFLICT")
        seen[key] = dict(bundle)
    return _ordered_unique(errors, EXPORT_RESULT_STATES)


def _attestation_errors(
    reconciliation: RuntimeLedgerReconciliationResult | dict[str, Any] | None,
    audit_record: dict[str, Any] | None,
    ledger_record: dict[str, Any] | None,
    context: ReconciliationAttestationContext,
) -> tuple[str, ...]:
    errors: list[str] = []
    reconciliation_payload = _payload(reconciliation)
    if reconciliation_payload.get("result") not in {"CONSISTENT", "ALREADY_RECONCILED"}:
        errors.append("RECONCILIATION_INVALID" if reconciliation_payload else "RECONCILIATION_REQUIRED")
    if not isinstance(audit_record, dict):
        errors.append("AUDIT_REFERENCE_MISSING")
        audit_record = {}
    elif verify_pipeline_persistence_records((audit_record,)):
        errors.append("AUDIT_REFERENCE_MISSING")
    if not isinstance(ledger_record, dict):
        errors.append("LEDGER_REFERENCE_MISSING")
        ledger_record = {}
    elif verify_runtime_ledger_persistence_records((ledger_record,)):
        errors.append("LEDGER_REFERENCE_MISSING")
    if not isinstance(context.issued_at, str) or not context.issued_at.strip() or not context.attestation_version:
        errors.append("MALFORMED_CONTEXT")
    if not _is_sha256_reference(context.audit_chain_reference) or not _is_sha256_reference(context.ledger_chain_reference):
        errors.append("CHAIN_REFERENCE_INVALID")
    if audit_record and ledger_record:
        _shared_reference_errors(reconciliation_payload, audit_record, ledger_record, errors)
    if _has_raw_marker({"context": context.__dict__, "audit": audit_record, "ledger": ledger_record}):
        errors.append("SERIALIZATION_FAILURE")
    return _ordered_unique(errors, ATTESTATION_RESULT_STATES)


def _export_errors(
    attestation: dict[str, Any] | None,
    audit_record: dict[str, Any] | None,
    ledger_record: dict[str, Any] | None,
    context: RegulatorExportBundleContext,
) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(attestation, dict):
        errors.append("ATTESTATION_REQUIRED")
        attestation = {}
    elif verify_reconciliation_attestation(attestation, reconciliation={"result": "CONSISTENT", **attestation}, audit_record=audit_record, ledger_record=ledger_record):
        errors.append("ATTESTATION_INVALID")
    if not isinstance(audit_record, dict):
        errors.append("AUDIT_REFERENCE_MISSING")
    if not isinstance(ledger_record, dict):
        errors.append("LEDGER_REFERENCE_MISSING")
    if not all(isinstance(value, str) and value.strip() for value in (context.export_profile, context.jurisdiction_reference, context.generated_at, context.bundle_version)):
        errors.append("MALFORMED_CONTEXT")
    if _has_raw_marker({"context": context.__dict__, "attestation": attestation}):
        errors.append("SERIALIZATION_FAILURE")
    return _ordered_unique(errors, EXPORT_RESULT_STATES)


def _shared_reference_errors(reconciliation_payload: dict[str, Any], audit_record: dict[str, Any], ledger_record: dict[str, Any], errors: list[str]) -> None:
    for field, code in (("correlation_id", "HASH_MISMATCH"), ("tenant", "TENANT_MISMATCH"), ("policy_version", "POLICY_VERSION_MISMATCH"), ("evidence_id", "EVIDENCE_ID_MISMATCH")):
        if audit_record.get(field) != ledger_record.get(field) or (reconciliation_payload.get(field) and reconciliation_payload.get(field) != audit_record.get(field)):
            errors.append(code)
    if audit_record.get("audit_hash") != ledger_record.get("audit_hash"):
        errors.append("HASH_MISMATCH")
    if audit_record.get("record_hash") != ledger_record.get("audit_record_hash"):
        errors.append("AUDIT_REFERENCE_MISSING")
    if reconciliation_payload.get("ledger_record_hash") and reconciliation_payload.get("ledger_record_hash") != ledger_record.get("ledger_entry_hash"):
        errors.append("LEDGER_REFERENCE_MISSING")
    if reconciliation_payload.get("report_hash") and not _is_sha256_reference(reconciliation_payload.get("report_hash")):
        errors.append("HASH_MISMATCH")


def _payload(value: RuntimeLedgerReconciliationResult | dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, RuntimeLedgerReconciliationResult):
        return value.to_dict()
    return dict(value)


def _ordered_unique(errors: list[str], order: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(code for code in order if code in errors)


def _false_execution_flags() -> dict[str, bool]:
    return {flag: False for flag in _EXECUTION_FLAGS}


def _is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _has_raw_marker(payload: Any) -> bool:
    serialized = canonical_audit_json(payload)
    lowered = serialized.lower()
    return any(marker in lowered for marker in _RAW_MARKERS)
