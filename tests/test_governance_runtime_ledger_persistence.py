from __future__ import annotations

import json

from governance.audit_evidence import (
    AUDIT_PIPELINE_STAGE_SEQUENCE,
    AuditEvidenceContext,
    attach_audit_evidence,
    build_audit_pipeline_summary,
    canonical_audit_json,
)
from governance.audit_evidence_persistence import (
    AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH,
    AuditPipelinePersistenceContext,
    append_pipeline_summary_record,
    build_pipeline_persistence_record,
)
from governance.runtime_ledger import (
    GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH,
    RuntimeLedgerDecisionContext,
    build_runtime_ledger_entry,
)
from governance.runtime_ledger_persistence import (
    RuntimeLedgerPersistenceContext,
    append_runtime_ledger_persistence_record,
    build_runtime_ledger_persistence_record,
    load_runtime_ledger_persistence_records,
    reconcile_runtime_ledger_references,
    reconcile_runtime_ledger_sets,
    runtime_ledger_persistence_schema,
    verify_runtime_ledger_persistence_records,
)


TIMESTAMP = "2026-05-12T00:20:00Z"


def _summary(*, tenant: str = "tenant-reconcile", policy_version: str = "policy.v1"):
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
    assert summary.valid is True
    return summary


def _audit_record(*, tenant: str = "tenant-reconcile", policy_version: str = "policy.v1") -> dict:
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


def _ledger_entry(audit_record: dict, *, decision: str = "BLOCKED", failure_code: str = "APPROVAL_REQUIRED") -> dict:
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


def _stored_record(audit_record: dict | None = None, ledger_entry: dict | None = None) -> dict:
    audit_record = audit_record or _audit_record()
    ledger_entry = ledger_entry or _ledger_entry(audit_record)
    return build_runtime_ledger_persistence_record(
        ledger_entry,
        audit_record,
        context=RuntimeLedgerPersistenceContext(
            checked_at=TIMESTAMP,
            expected_previous_hash=GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH,
        ),
        previous_hash=GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH,
        position=0,
    )


def test_persistence_schema_is_hash_only_and_execution_disabled() -> None:
    schema = runtime_ledger_persistence_schema()

    assert schema["payload_policy"] == "hash-only"
    assert schema["storage"] == "local-jsonl-append-only"
    assert schema["execution_allowed"] is False
    assert schema["provider_execution"] is False
    assert schema["production_activation"] is False
    assert schema["runtime_execution"] is False
    assert schema["deployment_execution"] is False
    assert schema["policy_mutation"] is False
    assert schema["network_access"] is False


def test_valid_audit_record_and_ledger_entry_reconcile() -> None:
    audit_record = _audit_record()
    ledger_entry = _ledger_entry(audit_record)
    stored = _stored_record(audit_record, ledger_entry)

    result = reconcile_runtime_ledger_references(
        summary=_summary(),
        audit_record=audit_record,
        ledger_entry=ledger_entry,
        stored_ledger_record=stored,
        checked_at=TIMESTAMP,
    )

    assert result.result == "CONSISTENT"
    assert result.failure_code == ""
    assert result.correlation_id == audit_record["correlation_id"]
    assert result.audit_record_hash == audit_record["record_hash"]
    assert result.ledger_record_hash == ledger_entry["entry_hash"]
    assert result.report_hash.startswith("sha256:")
    assert result.to_dict()["execution_allowed"] is False


def test_valid_append_extends_audit_and_ledger_chains(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    ledger_path = tmp_path / "ledger.jsonl"
    summary = _summary()

    audit_result = append_pipeline_summary_record(
        audit_path,
        summary,
        context=AuditPipelinePersistenceContext(
            evidence_id="evidence://local-only/sha256/" + ("a" * 64),
            governance_decision="BLOCKED",
            persisted_at=TIMESTAMP,
            expected_previous_hash=AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH,
        ),
    )
    audit_record = json.loads(audit_path.read_text(encoding="utf-8"))
    ledger_entry = _ledger_entry(audit_record)
    ledger_result = append_runtime_ledger_persistence_record(
        ledger_path,
        ledger_entry,
        audit_record,
        context=RuntimeLedgerPersistenceContext(
            checked_at=TIMESTAMP,
            expected_previous_hash=GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH,
        ),
    )

    records = load_runtime_ledger_persistence_records(ledger_path)
    assert audit_result.status == "PERSISTED"
    assert ledger_result.status == "PERSISTED"
    assert records[0]["previous_hash"] == GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH
    assert records[0]["ledger_previous_hash"] == GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH
    assert records[0]["audit_record_hash"] == audit_record["record_hash"]
    assert verify_runtime_ledger_persistence_records(records) == ()


def test_duplicate_reconcile_retry_is_idempotent(tmp_path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    audit_record = _audit_record()
    ledger_entry = _ledger_entry(audit_record)
    context = RuntimeLedgerPersistenceContext(checked_at=TIMESTAMP)

    first = append_runtime_ledger_persistence_record(ledger_path, ledger_entry, audit_record, context=context)
    repeated = append_runtime_ledger_persistence_record(
        ledger_path,
        ledger_entry,
        audit_record,
        context=RuntimeLedgerPersistenceContext(checked_at=TIMESTAMP, expected_previous_hash=first.record_hash),
    )

    assert first.status == "PERSISTED"
    assert repeated.status == "ALREADY_PERSISTED"
    assert repeated.written is False
    assert len(load_runtime_ledger_persistence_records(ledger_path)) == 1


def test_conflicting_retry_blocks_without_writing(tmp_path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    audit_record = _audit_record()
    ledger_entry = _ledger_entry(audit_record)
    first = append_runtime_ledger_persistence_record(
        ledger_path,
        ledger_entry,
        audit_record,
        context=RuntimeLedgerPersistenceContext(checked_at=TIMESTAMP),
    )
    conflicted = dict(ledger_entry)
    conflicted["failure_code"] = "POLICY_VERSION_MISMATCH"
    conflicted["ledger_id"] = "sha256:" + ("1" * 64)
    conflicted["entry_hash"] = "sha256:" + ("2" * 64)

    result = append_runtime_ledger_persistence_record(
        ledger_path,
        conflicted,
        audit_record,
        context=RuntimeLedgerPersistenceContext(checked_at=TIMESTAMP, expected_previous_hash=first.record_hash),
    )

    assert result.status == "BLOCKED"
    assert result.errors == ("MALFORMED_RECORD",)
    assert len(load_runtime_ledger_persistence_records(ledger_path)) == 1


def test_reconciliation_detects_mismatches_and_orphans() -> None:
    audit_record = _audit_record()
    ledger_entry = _ledger_entry(audit_record)
    tenant_changed = dict(ledger_entry)
    tenant_changed["tenant"] = "tenant-other"
    policy_changed = dict(ledger_entry)
    policy_changed["policy_version"] = "policy.v2"
    evidence_changed = dict(ledger_entry)
    evidence_changed["evidence_id"] = "evidence://local-only/sha256/" + ("b" * 64)
    audit_changed = dict(ledger_entry)
    audit_changed["audit_hash"] = "sha256:" + ("b" * 64)
    decision_changed = dict(ledger_entry)
    decision_changed["decision"] = "REVIEW_REQUIRED"
    failure_changed = dict(_stored_record(audit_record, ledger_entry))
    failure_changed["failure_code"] = "OTHER_REASON"

    assert reconcile_runtime_ledger_references(audit_record=None, ledger_entry=ledger_entry, stored_ledger_record=None, checked_at=TIMESTAMP).result == "AUDIT_RECORD_MISSING"
    assert reconcile_runtime_ledger_references(audit_record=audit_record, ledger_entry=None, stored_ledger_record=None, checked_at=TIMESTAMP).result == "LEDGER_RECORD_MISSING"
    assert reconcile_runtime_ledger_references(audit_record=audit_record, ledger_entry=tenant_changed, stored_ledger_record=None, checked_at=TIMESTAMP).result == "TENANT_MISMATCH"
    assert reconcile_runtime_ledger_references(audit_record=audit_record, ledger_entry=policy_changed, stored_ledger_record=None, checked_at=TIMESTAMP).result == "POLICY_VERSION_MISMATCH"
    assert reconcile_runtime_ledger_references(audit_record=audit_record, ledger_entry=evidence_changed, stored_ledger_record=None, checked_at=TIMESTAMP).result == "EVIDENCE_ID_MISMATCH"
    assert reconcile_runtime_ledger_references(audit_record=audit_record, ledger_entry=audit_changed, stored_ledger_record=None, checked_at=TIMESTAMP).result == "AUDIT_HASH_MISMATCH"
    assert reconcile_runtime_ledger_references(audit_record=audit_record, ledger_entry=decision_changed, stored_ledger_record=None, checked_at=TIMESTAMP).result == "DECISION_MISMATCH"
    assert reconcile_runtime_ledger_references(audit_record=audit_record, ledger_entry=ledger_entry, stored_ledger_record=failure_changed, checked_at=TIMESTAMP).result == "FAILURE_CODE_MISMATCH"


def test_read_only_set_reconciliation_detects_orphans() -> None:
    audit_record = _audit_record()
    ledger_entry = _ledger_entry(audit_record)
    stored = _stored_record(audit_record, ledger_entry)

    assert reconcile_runtime_ledger_sets(audit_records=(audit_record,), ledger_records=(), checked_at=TIMESTAMP).result == "LEDGER_RECORD_MISSING"
    assert reconcile_runtime_ledger_sets(audit_records=(), ledger_records=(stored,), checked_at=TIMESTAMP).result == "AUDIT_RECORD_MISSING"


def test_tamper_delete_reorder_and_duplicate_detection() -> None:
    audit_record = _audit_record()
    ledger_entry = _ledger_entry(audit_record)
    first = _stored_record(audit_record, ledger_entry)
    second_audit = _audit_record(tenant="tenant-second")
    second_entry = build_runtime_ledger_entry(
        RuntimeLedgerDecisionContext(
            timestamp=TIMESTAMP,
            tenant=second_audit["tenant"],
            policy_version=second_audit["policy_version"],
            validator="audit_pipeline",
            decision="BLOCKED",
            failure_code="APPROVAL_REQUIRED",
            evidence_id=second_audit["evidence_id"],
            audit_hash=second_audit["audit_hash"],
            correlation_id=second_audit["correlation_id"],
        ),
        previous_hash=first["record_hash"],
        position=1,
    )
    second = build_runtime_ledger_persistence_record(
        second_entry,
        second_audit,
        context=RuntimeLedgerPersistenceContext(checked_at=TIMESTAMP, expected_previous_hash=first["record_hash"]),
        previous_hash=first["record_hash"],
        position=1,
    )
    tampered = dict(first)
    tampered["tenant"] = "tenant-tampered"

    assert verify_runtime_ledger_persistence_records((first, second)) == ()
    assert "MALFORMED_RECORD" in verify_runtime_ledger_persistence_records((tampered,))
    assert "MALFORMED_RECORD" in verify_runtime_ledger_persistence_records((second,))
    assert "PREVIOUS_HASH_MISMATCH" in verify_runtime_ledger_persistence_records((second, first))
    assert "DUPLICATE_RECORD" in verify_runtime_ledger_persistence_records((first, first))


def test_cross_tenant_and_cross_policy_conflicts_are_detected() -> None:
    first = _stored_record()
    tenant_conflict = dict(first)
    tenant_conflict["position"] = 1
    tenant_conflict["previous_hash"] = first["record_hash"]
    tenant_conflict["correlation_id"] = "sha256:" + ("1" * 64)
    tenant_conflict["tenant"] = "tenant-other"
    tenant_conflict["record_hash"] = "sha256:" + ("2" * 64)
    policy_conflict = dict(first)
    policy_conflict["position"] = 1
    policy_conflict["previous_hash"] = first["record_hash"]
    policy_conflict["correlation_id"] = "sha256:" + ("3" * 64)
    policy_conflict["policy_version"] = "policy.v2"
    policy_conflict["record_hash"] = "sha256:" + ("4" * 64)

    assert "TENANT_MISMATCH" in verify_runtime_ledger_persistence_records((first, tenant_conflict))
    assert "POLICY_VERSION_MISMATCH" in verify_runtime_ledger_persistence_records((first, policy_conflict))


def test_raw_payload_markers_are_absent_and_rejected() -> None:
    stored = _stored_record()
    contaminated = dict(stored)
    contaminated["raw_payload"] = "customer-secret"
    serialized = canonical_audit_json(stored)

    assert "raw_payload" not in serialized
    assert "customer-secret" not in serialized
    assert "MALFORMED_RECORD" in verify_runtime_ledger_persistence_records((contaminated,))
