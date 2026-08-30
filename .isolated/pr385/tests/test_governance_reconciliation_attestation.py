from __future__ import annotations

from governance.audit_evidence import AUDIT_PIPELINE_STAGE_SEQUENCE, AuditEvidenceContext, attach_audit_evidence, build_audit_pipeline_summary, canonical_audit_json
from governance.audit_evidence_persistence import AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH, AuditPipelinePersistenceContext, build_pipeline_persistence_record
from governance.reconciliation_attestation import (
    ReconciliationAttestationContext,
    RegulatorExportBundleContext,
    build_reconciliation_attestation,
    build_regulator_export_bundle,
    build_signed_bundle_input,
    reconciliation_attestation_schema,
    verify_reconciliation_attestation,
    verify_regulator_export_bundle,
    verify_unique_attestations,
    verify_unique_export_bundles,
)
from governance.runtime_ledger import GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH, RuntimeLedgerDecisionContext, build_runtime_ledger_entry
from governance.runtime_ledger_persistence import (
    RuntimeLedgerPersistenceContext,
    build_runtime_ledger_persistence_record,
    reconcile_runtime_ledger_references,
)


TIMESTAMP = "2026-05-12T00:20:00Z"
AUDIT_CHAIN_REFERENCE = "sha256:" + ("8" * 64)
LEDGER_CHAIN_REFERENCE = "sha256:" + ("9" * 64)


def _summary(*, tenant: str = "tenant-attestation", policy_version: str = "policy.v1"):
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
    return build_audit_pipeline_summary(tuple(evidences))


def _audit_record(*, tenant: str = "tenant-attestation", policy_version: str = "policy.v1"):
    return build_pipeline_persistence_record(
        _summary(tenant=tenant, policy_version=policy_version),
        context=AuditPipelinePersistenceContext(
            evidence_id="evidence://local-only/sha256/" + ("a" * 64),
            governance_decision="BLOCKED",
            persisted_at=TIMESTAMP,
            expected_previous_hash=AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH,
        ),
        previous_hash=AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH,
        position=0,
    )


def _ledger_entry(audit_record: dict, *, decision: str = "BLOCKED", failure_code: str = "APPROVAL_REQUIRED"):
    return build_runtime_ledger_entry(
        RuntimeLedgerDecisionContext(
            timestamp=TIMESTAMP,
            tenant=audit_record["tenant"],
            policy_version=audit_record["policy_version"],
            validator="audit_pipeline",
            decision=decision,
            failure_code=failure_code,
            evidence_id=audit_record["evidence_id"],
            audit_hash=audit_record["audit_hash"],
            correlation_id=audit_record["correlation_id"],
        ),
        previous_hash=GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH,
        position=0,
    )


def _fixtures():
    audit_record = _audit_record()
    ledger_entry = _ledger_entry(audit_record)
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
        context=ReconciliationAttestationContext(
            issued_at=TIMESTAMP,
            audit_chain_reference=AUDIT_CHAIN_REFERENCE,
            ledger_chain_reference=LEDGER_CHAIN_REFERENCE,
        ),
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
    return audit_record, ledger_record, reconciliation, attestation, bundle


def test_schema_is_hash_only_and_execution_disabled() -> None:
    schema = reconciliation_attestation_schema()

    assert schema["payload_policy"] == "hash-only"
    assert schema["execution_allowed"] is False
    assert schema["provider_execution"] is False
    assert schema["production_activation"] is False
    assert schema["runtime_execution"] is False
    assert schema["deployment_execution"] is False
    assert schema["policy_mutation"] is False
    assert schema["network_access"] is False


def test_valid_reconciled_input_creates_deterministic_attestation() -> None:
    audit_record, ledger_record, reconciliation, attestation, _bundle = _fixtures()
    repeated = build_reconciliation_attestation(
        reconciliation=reconciliation,
        audit_record=dict(reversed(audit_record.items())),
        ledger_record=dict(reversed(ledger_record.items())),
        context=ReconciliationAttestationContext(
            issued_at=TIMESTAMP,
            audit_chain_reference=AUDIT_CHAIN_REFERENCE,
            ledger_chain_reference=LEDGER_CHAIN_REFERENCE,
        ),
    )

    assert repeated.result == "ATTESTATION_VALID"
    assert repeated.attestation == attestation
    assert verify_reconciliation_attestation(attestation, reconciliation=reconciliation, audit_record=audit_record, ledger_record=ledger_record) == ()
    assert attestation["governance_decision"] == "BLOCKED"
    assert attestation["execution_allowed"] is False


def test_attestation_hash_changes_for_bound_reference_changes() -> None:
    audit_record, ledger_record, reconciliation, attestation, _bundle = _fixtures()

    tenant_record = dict(audit_record)
    tenant_record["tenant"] = "tenant-other"
    policy_record = dict(audit_record)
    policy_record["policy_version"] = "policy.v2"
    evidence_record = dict(audit_record)
    evidence_record["evidence_id"] = "evidence://local-only/sha256/" + ("b" * 64)
    decision_ledger = dict(ledger_record)
    decision_ledger["governance_decision"] = "REVIEW_REQUIRED"
    failure_ledger = dict(ledger_record)
    failure_ledger["failure_code"] = "OTHER_REASON"
    audit_hash_ledger = dict(ledger_record)
    audit_hash_ledger["audit_hash"] = "sha256:" + ("b" * 64)
    ledger_hash = dict(ledger_record)
    ledger_hash["ledger_entry_hash"] = "sha256:" + ("c" * 64)
    report_hash = reconciliation.to_dict()
    report_hash["report_hash"] = "sha256:" + ("d" * 64)

    def _hash(audit=audit_record, ledger=ledger_record, recon=reconciliation, audit_ref=AUDIT_CHAIN_REFERENCE):
        return build_reconciliation_attestation(
            reconciliation=recon,
            audit_record=audit,
            ledger_record=ledger,
            context=ReconciliationAttestationContext(
                issued_at=TIMESTAMP,
                audit_chain_reference=audit_ref,
                ledger_chain_reference=LEDGER_CHAIN_REFERENCE,
            ),
        ).attestation

    assert _hash(audit=tenant_record) is None
    assert _hash(audit=policy_record) is None
    assert _hash(audit=evidence_record) is None
    assert _hash(ledger=decision_ledger) is None
    assert _hash(ledger=failure_ledger) is None
    assert _hash(ledger=audit_hash_ledger) is None
    assert _hash(ledger=ledger_hash) is None
    changed_chain = _hash(audit_ref="sha256:" + ("e" * 64))
    assert changed_chain is not None
    assert changed_chain["attestation_hash"] != attestation["attestation_hash"]
    changed_report = _hash(recon=report_hash)
    assert changed_report is not None
    assert changed_report["attestation_hash"] != attestation["attestation_hash"]


def test_invalid_reconciliation_and_missing_references_fail_closed() -> None:
    audit_record, ledger_record, reconciliation, _attestation, _bundle = _fixtures()
    invalid = reconciliation.to_dict()
    invalid["result"] = "TENANT_MISMATCH"

    assert build_reconciliation_attestation(reconciliation=None, audit_record=audit_record, ledger_record=ledger_record, context=ReconciliationAttestationContext(TIMESTAMP, AUDIT_CHAIN_REFERENCE, LEDGER_CHAIN_REFERENCE)).result == "RECONCILIATION_REQUIRED"
    assert build_reconciliation_attestation(reconciliation=invalid, audit_record=audit_record, ledger_record=ledger_record, context=ReconciliationAttestationContext(TIMESTAMP, AUDIT_CHAIN_REFERENCE, LEDGER_CHAIN_REFERENCE)).result == "RECONCILIATION_INVALID"
    assert build_reconciliation_attestation(reconciliation=reconciliation, audit_record=None, ledger_record=ledger_record, context=ReconciliationAttestationContext(TIMESTAMP, AUDIT_CHAIN_REFERENCE, LEDGER_CHAIN_REFERENCE)).result == "AUDIT_REFERENCE_MISSING"
    assert build_reconciliation_attestation(reconciliation=reconciliation, audit_record=audit_record, ledger_record=None, context=ReconciliationAttestationContext(TIMESTAMP, AUDIT_CHAIN_REFERENCE, LEDGER_CHAIN_REFERENCE)).result == "LEDGER_REFERENCE_MISSING"
    assert build_reconciliation_attestation(reconciliation=reconciliation, audit_record=audit_record, ledger_record=ledger_record, context=ReconciliationAttestationContext(TIMESTAMP, "not-a-hash", LEDGER_CHAIN_REFERENCE)).result == "CHAIN_REFERENCE_INVALID"


def test_export_bundle_is_deterministic_and_reference_only() -> None:
    audit_record, ledger_record, _reconciliation, attestation, bundle = _fixtures()
    repeated = build_regulator_export_bundle(
        attestation=dict(reversed(attestation.items())),
        audit_record=dict(reversed(audit_record.items())),
        ledger_record=dict(reversed(ledger_record.items())),
        context=RegulatorExportBundleContext(
            export_profile="regulator-profile://local-only/eu-ai-act",
            jurisdiction_reference="jurisdiction://EU/reference-only",
            generated_at=TIMESTAMP,
            signed_auditor_bundle_reference="sha256:" + ("1" * 64),
            sealed_archive_reference="sha256:" + ("2" * 64),
            worm_reference="sha256:" + ("3" * 64),
            timestamp_reference="sha256:" + ("4" * 64),
        ),
    )

    assert repeated.result == "EXPORT_BUNDLE_VALID"
    assert repeated.bundle == bundle
    assert verify_regulator_export_bundle(bundle, attestation=attestation, audit_record=audit_record, ledger_record=ledger_record) == ()
    assert "raw_payload" not in canonical_audit_json(bundle)
    assert bundle["production_activation"] is False


def test_export_bundle_negative_paths_and_duplicates() -> None:
    audit_record, ledger_record, _reconciliation, attestation, bundle = _fixtures()
    bad_attestation = dict(attestation)
    bad_attestation["tenant"] = "tenant-other"
    bad_bundle = dict(bundle)
    bad_bundle["audit_record_reference"] = "sha256:" + ("b" * 64)
    contaminated = dict(bundle)
    contaminated["raw_payload"] = "customer-secret"
    conflict = dict(attestation)
    conflict["attestation_hash"] = "sha256:" + ("f" * 64)

    assert build_regulator_export_bundle(attestation=None, audit_record=audit_record, ledger_record=ledger_record, context=RegulatorExportBundleContext("profile", "jurisdiction", TIMESTAMP)).result == "ATTESTATION_REQUIRED"
    assert build_regulator_export_bundle(attestation=bad_attestation, audit_record=audit_record, ledger_record=ledger_record, context=RegulatorExportBundleContext("profile", "jurisdiction", TIMESTAMP)).result == "ATTESTATION_INVALID"
    assert "AUDIT_REFERENCE_MISSING" in verify_regulator_export_bundle(bad_bundle, attestation=attestation, audit_record=audit_record, ledger_record=ledger_record)
    assert "SERIALIZATION_FAILURE" in verify_regulator_export_bundle(contaminated, attestation=attestation, audit_record=audit_record, ledger_record=ledger_record)
    assert verify_unique_attestations((attestation, attestation)) == ("DUPLICATE_ATTESTATION",)
    assert verify_unique_attestations((attestation, conflict)) == ("ATTESTATION_CONFLICT",)
    assert verify_unique_export_bundles((bundle, bundle)) == ("DUPLICATE_ATTESTATION",)


def test_signed_bundle_input_binds_required_hashes_and_references() -> None:
    audit_record, ledger_record, _reconciliation, attestation, bundle = _fixtures()
    signing_input = build_signed_bundle_input(bundle, attestation)

    assert signing_input["reconciliation_attestation_hash"] == attestation["attestation_hash"]
    assert signing_input["regulator_export_bundle_manifest_hash"] == bundle["bundle_manifest_hash"]
    assert signing_input["audit_record_hash"] == audit_record["record_hash"]
    assert signing_input["runtime_ledger_record_hash"] == ledger_record["record_hash"]
    assert signing_input["audit_chain_reference"] == AUDIT_CHAIN_REFERENCE
    assert signing_input["ledger_chain_reference"] == LEDGER_CHAIN_REFERENCE
    assert signing_input["execution_allowed"] is False
    assert signing_input["signing_input_hash"].startswith("sha256:")
