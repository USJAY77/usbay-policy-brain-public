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
    audit_pipeline_persistence_schema,
    build_pipeline_persistence_record,
    load_pipeline_persistence_records,
    verify_pipeline_persistence_records,
)


TIMESTAMP = "2026-05-12T00:20:00Z"


def _pipeline_summary(*, tenant: str = "tenant-persistence", policy_version: str = "policy.v1"):
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


def _context(*, previous_hash: str = AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH) -> AuditPipelinePersistenceContext:
    return AuditPipelinePersistenceContext(
        evidence_id="evidence://local-only/sha256/" + ("a" * 64),
        governance_decision="BLOCKED",
        persisted_at=TIMESTAMP,
        expected_previous_hash=previous_hash,
    )


def test_persistence_schema_is_hash_only_and_local_only() -> None:
    schema = audit_pipeline_persistence_schema()

    assert schema["payload_policy"] == "hash-only"
    assert schema["storage"] == "local-jsonl-append-only"
    assert schema["execution_allowed"] is False
    assert schema["provider_execution"] is False
    assert schema["production_activation"] is False
    assert tuple(schema["pipeline_stage_sequence"]) == AUDIT_PIPELINE_STAGE_SEQUENCE


def test_valid_append_extends_chain_with_previous_hash_binding(tmp_path) -> None:
    storage = tmp_path / "audit-pipeline.jsonl"
    summary = _pipeline_summary()

    first = append_pipeline_summary_record(storage, summary, context=_context())
    second_summary = _pipeline_summary(tenant="tenant-persistence-b")
    second = append_pipeline_summary_record(
        storage,
        second_summary,
        context=_context(previous_hash=first.record_hash),
    )

    records = load_pipeline_persistence_records(storage)
    assert first.status == "PERSISTED"
    assert first.written is True
    assert second.status == "PERSISTED"
    assert second.previous_hash == first.record_hash
    assert len(records) == 2
    assert verify_pipeline_persistence_records(records) == ()
    assert all(record["execution_allowed"] is False for record in records)
    assert all(record["provider_execution"] is False for record in records)
    assert all(record["production_activation"] is False for record in records)


def test_append_rejects_invalid_pipeline_summary_without_writing(tmp_path) -> None:
    storage = tmp_path / "audit-pipeline.jsonl"
    summary = build_audit_pipeline_summary(())

    result = append_pipeline_summary_record(storage, summary, context=_context())

    assert result.status == "BLOCKED"
    assert result.errors == ("AUDIT_PIPELINE_PERSISTENCE_SUMMARY_INVALID",)
    assert result.written is False
    assert load_pipeline_persistence_records(storage) == ()


def test_duplicate_identical_correlation_is_idempotent(tmp_path) -> None:
    storage = tmp_path / "audit-pipeline.jsonl"
    summary = _pipeline_summary()

    first = append_pipeline_summary_record(storage, summary, context=_context())
    repeated = append_pipeline_summary_record(storage, summary, context=_context(previous_hash=first.record_hash))

    assert repeated.status == "ALREADY_PERSISTED"
    assert repeated.written is False
    assert len(load_pipeline_persistence_records(storage)) == 1


def test_duplicate_correlation_with_different_content_blocks(tmp_path) -> None:
    storage = tmp_path / "audit-pipeline.jsonl"
    summary = _pipeline_summary()
    first = append_pipeline_summary_record(storage, summary, context=_context())
    conflicted = summary.to_dict()
    conflicted["canonical_payload_hashes"] = list(reversed(conflicted["canonical_payload_hashes"]))

    result = append_pipeline_summary_record(storage, conflicted, context=_context(previous_hash=first.record_hash))

    assert result.status == "BLOCKED"
    assert result.errors == ("AUDIT_PIPELINE_PERSISTENCE_CORRELATION_CONFLICT",)
    assert len(load_pipeline_persistence_records(storage)) == 1


def test_stale_previous_hash_blocks_without_partial_state(tmp_path) -> None:
    storage = tmp_path / "audit-pipeline.jsonl"
    first = append_pipeline_summary_record(storage, _pipeline_summary(), context=_context())

    result = append_pipeline_summary_record(
        storage,
        _pipeline_summary(tenant="tenant-other"),
        context=_context(previous_hash=AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH),
    )

    assert first.status == "PERSISTED"
    assert result.status == "BLOCKED"
    assert result.errors == ("AUDIT_PIPELINE_PERSISTENCE_PREVIOUS_HASH_MISMATCH",)
    assert len(load_pipeline_persistence_records(storage)) == 1


def test_malformed_tail_blocks_future_append(tmp_path) -> None:
    storage = tmp_path / "audit-pipeline.jsonl"
    append_pipeline_summary_record(storage, _pipeline_summary(), context=_context())
    storage.write_text(storage.read_text(encoding="utf-8") + '{"partial":', encoding="utf-8")

    result = append_pipeline_summary_record(
        storage,
        _pipeline_summary(tenant="tenant-other"),
        context=_context(previous_hash="sha256:" + ("1" * 64)),
    )

    assert result.status == "BLOCKED"
    assert result.errors == ("AUDIT_PIPELINE_PERSISTENCE_RECORD_MALFORMED",)


def test_tamper_delete_reorder_and_duplicate_are_detected() -> None:
    first = build_pipeline_persistence_record(
        _pipeline_summary(),
        context=_context(),
        previous_hash=AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH,
        position=0,
    )
    second = build_pipeline_persistence_record(
        _pipeline_summary(tenant="tenant-b"),
        context=_context(previous_hash=first["record_hash"]),
        previous_hash=first["record_hash"],
        position=1,
    )
    tampered = dict(second)
    tampered["tenant"] = "tenant-c"
    duplicate = dict(first)

    assert verify_pipeline_persistence_records((first, second)) == ()
    assert "AUDIT_PIPELINE_PERSISTENCE_RECORD_HASH_MISMATCH" in verify_pipeline_persistence_records((first, tampered))
    assert "AUDIT_PIPELINE_PERSISTENCE_POSITION_INVALID" in verify_pipeline_persistence_records((second,))
    assert "AUDIT_PIPELINE_PERSISTENCE_PREVIOUS_HASH_MISMATCH" in verify_pipeline_persistence_records((second, first))
    assert "AUDIT_PIPELINE_PERSISTENCE_CORRELATION_DUPLICATE" in verify_pipeline_persistence_records((first, duplicate))


def test_tenant_and_policy_crossover_for_same_audit_hash_are_detected() -> None:
    first = build_pipeline_persistence_record(
        _pipeline_summary(),
        context=_context(),
        previous_hash=AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH,
        position=0,
    )
    tenant_crossover = dict(first)
    tenant_crossover["position"] = 1
    tenant_crossover["previous_hash"] = first["record_hash"]
    tenant_crossover["correlation_id"] = "sha256:" + ("1" * 64)
    tenant_crossover["tenant"] = "tenant-crossover"
    tenant_crossover["record_hash"] = "sha256:" + ("2" * 64)
    policy_crossover = dict(first)
    policy_crossover["position"] = 1
    policy_crossover["previous_hash"] = first["record_hash"]
    policy_crossover["correlation_id"] = "sha256:" + ("3" * 64)
    policy_crossover["policy_version"] = "policy.v2"
    policy_crossover["record_hash"] = "sha256:" + ("4" * 64)

    tenant_errors = verify_pipeline_persistence_records((first, tenant_crossover))
    policy_errors = verify_pipeline_persistence_records((first, policy_crossover))

    assert "AUDIT_PIPELINE_PERSISTENCE_TENANT_CROSSOVER" in tenant_errors
    assert "AUDIT_PIPELINE_PERSISTENCE_POLICY_VERSION_CROSSOVER" in policy_errors


def test_raw_payload_markers_are_absent_and_rejected(tmp_path) -> None:
    storage = tmp_path / "audit-pipeline.jsonl"
    record = build_pipeline_persistence_record(
        _pipeline_summary(),
        context=_context(),
        previous_hash=AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH,
        position=0,
    )
    serialized = canonical_audit_json(record)
    contaminated = dict(record)
    contaminated["raw_payload"] = "customer-secret"

    assert "customer-secret" not in serialized
    assert "raw_payload" not in serialized
    assert verify_pipeline_persistence_records((contaminated,)) == (
        "AUDIT_PIPELINE_PERSISTENCE_RECORD_HASH_MISMATCH",
        "AUDIT_PIPELINE_PERSISTENCE_RAW_DATA_FORBIDDEN",
    )

    result = append_pipeline_summary_record(
        storage,
        _pipeline_summary(),
        context=AuditPipelinePersistenceContext(
            evidence_id="evidence://local-only/sha256/" + ("a" * 64),
            governance_decision="BLOCKED",
            persisted_at=TIMESTAMP,
            expected_previous_hash=AUDIT_PIPELINE_PERSISTENCE_GENESIS_HASH,
        ),
    )
    assert json.loads(storage.read_text(encoding="utf-8"))["record_hash"] == result.record_hash
