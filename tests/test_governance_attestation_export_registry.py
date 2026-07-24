from __future__ import annotations

import json

from governance.attestation_export_registry import (
    REGISTRY_GENESIS_HASH,
    RegistryAppendContext,
    append_attestation_registry_record,
    append_export_bundle_registry_record,
    attestation_export_registry_schema,
    build_attestation_registry_record,
    build_cross_registry_report,
    build_export_bundle_registry_record,
    load_registry_records,
    verify_registry_records,
)
from governance.audit_evidence import AUDIT_PIPELINE_STAGE_SEQUENCE, AuditEvidenceContext, attach_audit_evidence, build_audit_pipeline_summary, canonical_audit_json
from governance.audit_evidence_persistence import AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH, AuditPipelinePersistenceContext, build_pipeline_persistence_record
from governance.reconciliation_attestation import (
    ReconciliationAttestationContext,
    RegulatorExportBundleContext,
    build_reconciliation_attestation,
    build_regulator_export_bundle,
)
from governance.runtime_ledger import GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH, RuntimeLedgerDecisionContext, build_runtime_ledger_entry
from governance.runtime_ledger_persistence import RuntimeLedgerPersistenceContext, build_runtime_ledger_persistence_record, reconcile_runtime_ledger_references


TIMESTAMP = "2026-05-12T00:20:00Z"
AUDIT_CHAIN_REFERENCE = "sha256:" + ("8" * 64)
LEDGER_CHAIN_REFERENCE = "sha256:" + ("9" * 64)


def _fixtures(tenant: str = "tenant-registry", policy_version: str = "policy.v1"):
    evidences = []
    for index, validator in enumerate(AUDIT_PIPELINE_STAGE_SEQUENCE):
        attached = attach_audit_evidence(
            {"valid": True, "errors": []},
            canonical_payload={"stage": validator, "position": index},
            context=AuditEvidenceContext(
                validator=validator,
                timestamp=TIMESTAMP,
                policy_version=policy_version,
                tenant=tenant,
                evidence_id=f"evidence://local-only/sha256/{index:064x}",
            ),
        )
        assert attached.audit_evidence is not None
        evidences.append(attached.audit_evidence)
    summary = build_audit_pipeline_summary(tuple(evidences))
    audit_record = build_pipeline_persistence_record(
        summary,
        context=AuditPipelinePersistenceContext(
            evidence_id="evidence://local-only/sha256/" + ("a" * 64),
            governance_decision="BLOCKED",
            persisted_at=TIMESTAMP,
            expected_previous_hash=AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH,
        ),
        previous_hash=AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH,
        position=0,
    )
    ledger_entry = build_runtime_ledger_entry(
        RuntimeLedgerDecisionContext(
            timestamp=TIMESTAMP,
            tenant=audit_record["tenant"],
            policy_version=audit_record["policy_version"],
            validator="audit_pipeline",
            decision="BLOCKED",
            failure_code="APPROVAL_REQUIRED",
            evidence_id=audit_record["evidence_id"],
            audit_hash=audit_record["audit_hash"],
            correlation_id=audit_record["correlation_id"],
        ),
        previous_hash=GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH,
        position=0,
    )
    ledger_record = build_runtime_ledger_persistence_record(
        ledger_entry,
        audit_record,
        context=RuntimeLedgerPersistenceContext(checked_at=TIMESTAMP),
        previous_hash=GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH,
        position=0,
    )
    reconciliation = reconcile_runtime_ledger_references(
        audit_record=audit_record,
        ledger_entry=ledger_entry,
        stored_ledger_record=ledger_record,
        checked_at=TIMESTAMP,
    )
    attestation = build_reconciliation_attestation(
        reconciliation=reconciliation,
        audit_record=audit_record,
        ledger_record=ledger_record,
        context=ReconciliationAttestationContext(TIMESTAMP, AUDIT_CHAIN_REFERENCE, LEDGER_CHAIN_REFERENCE),
    ).attestation
    assert attestation is not None
    bundle = build_regulator_export_bundle(
        attestation=attestation,
        audit_record=audit_record,
        ledger_record=ledger_record,
        context=RegulatorExportBundleContext(
            export_profile="regulator-profile://local-only/eu-ai-act",
            jurisdiction_reference="jurisdiction://EU/reference-only",
            generated_at=TIMESTAMP,
            signed_auditor_bundle_reference="sha256:" + ("1" * 64),
            sealed_archive_reference="sha256:" + ("2" * 64),
            worm_reference="sha256:" + ("3" * 64),
            timestamp_reference="sha256:" + ("4" * 64),
        ),
    ).bundle
    assert bundle is not None
    attestation_record = build_attestation_registry_record(
        attestation,
        reconciliation=reconciliation.to_dict(),
        audit_record=audit_record,
        ledger_record=ledger_record,
    )
    export_record = build_export_bundle_registry_record(
        bundle,
        attestation_record=attestation_record,
        attestation=attestation,
        audit_record=audit_record,
        ledger_record=ledger_record,
        previous_registry_hash=attestation_record["registry_record_hash"],
        position=1,
    )
    return audit_record, ledger_record, reconciliation.to_dict(), attestation, bundle, attestation_record, export_record


def test_registry_schema_is_hash_only_and_execution_disabled() -> None:
    schema = attestation_export_registry_schema()

    assert schema["payload_policy"] == "hash-only"
    assert schema["storage"] == "local-jsonl-append-only"
    assert schema["execution_allowed"] is False
    assert schema["provider_execution"] is False
    assert schema["production_activation"] is False
    assert schema["runtime_execution"] is False
    assert schema["deployment_execution"] is False
    assert schema["policy_mutation"] is False
    assert schema["network_access"] is False


def test_valid_attestation_and_export_persist_once_with_idempotent_retry(tmp_path) -> None:
    path = tmp_path / "registry.jsonl"
    audit_record, ledger_record, reconciliation, attestation, bundle, _attestation_record, _export_record = _fixtures()

    first = append_attestation_registry_record(path, attestation, reconciliation=reconciliation, audit_record=audit_record, ledger_record=ledger_record)
    repeated = append_attestation_registry_record(
        path,
        attestation,
        reconciliation=reconciliation,
        audit_record=audit_record,
        ledger_record=ledger_record,
        context=RegistryAppendContext(expected_previous_hash=first.registry_record_hash),
    )
    records = load_registry_records(path)
    export = append_export_bundle_registry_record(
        path,
        bundle,
        attestation_record=records[0],
        attestation=attestation,
        audit_record=audit_record,
        ledger_record=ledger_record,
        context=RegistryAppendContext(expected_previous_hash=first.registry_record_hash),
    )

    assert first.status == "PERSISTED"
    assert repeated.status == "ALREADY_PERSISTED"
    assert repeated.written is False
    assert export.status == "PERSISTED"
    assert verify_registry_records(load_registry_records(path)) == ()


def test_valid_records_have_deterministic_hashes_and_reference_only_payload() -> None:
    _audit_record, _ledger_record, _reconciliation, _attestation, _bundle, attestation_record, export_record = _fixtures()
    repeated = _fixtures()[-2:]

    assert repeated[0] == attestation_record
    assert repeated[1] == export_record
    serialized = canonical_audit_json({"attestation": attestation_record, "export": export_record})
    assert "raw_payload" not in serialized
    assert "approval_content" not in serialized
    assert attestation_record["governance_decision"] == "BLOCKED"
    assert export_record["production_activation"] is False


def test_invalid_attestation_and_export_are_blocked() -> None:
    audit_record, ledger_record, reconciliation, attestation, bundle, attestation_record, _export_record = _fixtures()
    bad_attestation = dict(attestation)
    bad_attestation["attestation_hash"] = "sha256:" + ("f" * 64)
    bad_bundle = dict(bundle)
    bad_bundle["bundle_manifest_hash"] = "sha256:" + ("e" * 64)

    try:
        build_attestation_registry_record(bad_attestation, reconciliation=reconciliation, audit_record=audit_record, ledger_record=ledger_record)
    except ValueError as exc:
        assert str(exc) == "ATTESTATION_INVALID"
    else:
        raise AssertionError("invalid attestation persisted")

    try:
        build_export_bundle_registry_record(bad_bundle, attestation_record=attestation_record, attestation=attestation, audit_record=audit_record, ledger_record=ledger_record)
    except ValueError as exc:
        assert str(exc) == "EXPORT_BUNDLE_INVALID"
    else:
        raise AssertionError("invalid export persisted")


def test_chain_integrity_detects_deletion_reorder_insertion_duplicate_and_mutation() -> None:
    *_base, attestation_record, export_record = _fixtures()
    tampered = dict(attestation_record)
    tampered["tenant"] = "tenant-other"
    inserted = dict(export_record)
    inserted["position"] = 2
    inserted["previous_registry_hash"] = export_record["registry_record_hash"]
    inserted["registry_record_hash"] = "sha256:" + ("b" * 64)

    assert verify_registry_records((attestation_record, export_record)) == ()
    assert "REGISTRY_TAMPERED" in verify_registry_records((tampered,))
    assert "REGISTRY_REORDERED" in verify_registry_records((export_record,))
    assert "CHAIN_INVALID" in verify_registry_records((export_record, attestation_record))
    assert "DUPLICATE_RECORD" in verify_registry_records((attestation_record, attestation_record))
    insertion_errors = verify_registry_records((attestation_record, inserted))
    assert "CHAIN_INVALID" in insertion_errors
    assert "REGISTRY_TAMPERED" in insertion_errors


def test_malformed_tail_and_locked_registry_block_append(tmp_path) -> None:
    path = tmp_path / "registry.jsonl"
    audit_record, ledger_record, reconciliation, attestation, _bundle, _attestation_record, _export_record = _fixtures()
    path.write_text('{"partial":', encoding="utf-8")

    result = append_attestation_registry_record(path, attestation, reconciliation=reconciliation, audit_record=audit_record, ledger_record=ledger_record)
    assert result.status == "FAILED_CLOSED"
    assert result.errors == ("MALFORMED_RECORD",)

    path.write_text("", encoding="utf-8")
    lock = path.with_suffix(path.suffix + ".lock")
    lock.write_text("locked", encoding="utf-8")
    locked = append_attestation_registry_record(path, attestation, reconciliation=reconciliation, audit_record=audit_record, ledger_record=ledger_record)
    assert locked.status == "LOCKED"


def test_raw_secret_credential_private_key_and_approval_markers_block() -> None:
    *_base, attestation_record, _export_record = _fixtures()

    for marker in ("raw_payload", "secret", "credential", "private_key", "approval_content"):
        contaminated = dict(attestation_record)
        contaminated[marker] = "blocked"
        assert "SERIALIZATION_FAILURE" in verify_registry_records((contaminated,))


def test_cross_registry_report_is_deterministic_and_detects_missing_and_mismatch() -> None:
    audit_record, ledger_record, _reconciliation, _attestation, _bundle, attestation_record, export_record = _fixtures()

    report = build_cross_registry_report(
        audit_record=audit_record,
        ledger_record=ledger_record,
        attestation_record=attestation_record,
        export_record=export_record,
        generated_at=TIMESTAMP,
    )
    repeated = build_cross_registry_report(
        audit_record=dict(reversed(audit_record.items())),
        ledger_record=dict(reversed(ledger_record.items())),
        attestation_record=dict(reversed(attestation_record.items())),
        export_record=dict(reversed(export_record.items())),
        generated_at=TIMESTAMP,
    )
    missing = build_cross_registry_report(
        audit_record=audit_record,
        ledger_record=ledger_record,
        attestation_record=None,
        export_record=export_record,
        generated_at=TIMESTAMP,
    )
    mismatch = dict(export_record)
    mismatch["tenant"] = "tenant-other"
    mismatch["registry_record_hash"] = "sha256:" + ("c" * 64)
    mismatch_report = build_cross_registry_report(
        audit_record=audit_record,
        ledger_record=ledger_record,
        attestation_record=attestation_record,
        export_record=mismatch,
        generated_at=TIMESTAMP,
    )

    assert report.result == "CONSISTENT"
    assert report.report_hash == repeated.report_hash
    assert missing.result == "ATTESTATION_MISSING"
    assert mismatch_report.result in {"TENANT_MISMATCH", "TAMPERED"}
    assert report.to_dict()["execution_allowed"] is False


def test_cross_tenant_and_policy_isolation_changes_hashes() -> None:
    tenant_record = _fixtures(tenant="tenant-b")[-2]
    policy_record = _fixtures(policy_version="policy.v2")[-2]
    base_record = _fixtures()[-2]

    assert tenant_record["tenant"] != base_record["tenant"]
    assert tenant_record["registry_record_hash"] != base_record["registry_record_hash"]
    assert policy_record["policy_version"] != base_record["policy_version"]
    assert policy_record["registry_record_hash"] != base_record["registry_record_hash"]
