from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from pathlib import Path

from publication.audit_persistence import LocalAuditStore, create_publication_audit_event
from publication.classification import classify_registry_record
from publication.connector_gate import evaluate_connector_gate
from publication.decision_engine import evaluate_publication_decision
from publication.human_approval import resolve_human_approval
from publication.models import (
    ApprovalEvidence,
    BlockReason,
    PublicationAuditEvent,
    PublicationDecision,
    RegistryRecord,
)
from publication.registry_store import load_json_file
from publication.registry_validator import validate_registry_record
from publication.sensitive_data_scanner import scan_publication_content


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "policy" / "publication" / "publication_registry_record.example.json"
APPROVAL_POLICY_PATH = ROOT / "policy" / "publication" / "publication_approval_policy.json"
NOW = datetime.fromisoformat("2026-06-25T00:00:00+00:00")


def example_record(**overrides: object) -> RegistryRecord:
    data = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
    data.update(overrides)
    return RegistryRecord.from_dict(data)


def approval(record: RegistryRecord):
    evidence = ApprovalEvidence.from_dict(
        {
            "artifact_id": record.artifact_id,
            "artifact_version": record.version,
            "owner": record.owner,
            "reviewer": record.reviewer,
            "reviewer_role": "Publication Reviewer",
            "approval_state": "APPROVED",
            "approval_timestamp": "2026-06-24T00:00:00Z",
            "approval_hash": record.approval_hash,
            "policy_version": record.policy_version,
            "audit_reference": record.audit_reference,
            "rollback_reference": record.rollback_reference,
            "classification": record.classification,
        }
    )
    return resolve_human_approval(
        record=record,
        approvals=[evidence],
        policy=load_json_file(APPROVAL_POLICY_PATH),
        now=NOW,
    )


def scan(record: RegistryRecord):
    return scan_publication_content(
        artifact_id=record.artifact_id,
        content="Approved public governance announcement.",
    )


def audit_event(record: RegistryRecord, *, store: LocalAuditStore | None = None):
    scan_result = scan(record)
    approval_result = approval(record)
    return create_publication_audit_event(
        record=record,
        decision=PublicationDecision.ALLOW_PUBLICATION,
        block_reason=BlockReason.NONE,
        sensitive_scan_hash=scan_result.audit.evidence_hashes["sensitive_scan_hash"],
        approval_hash=approval_result.audit.evidence_hashes["approval_validation_hash"],
        validator_hash="sha256:example_validator_hash_replace_before_use",
        store=store,
    )


def connector(record: RegistryRecord, scan_result, approval_result, audit_result):
    return evaluate_connector_gate(
        record=record,
        registry_result=validate_registry_record(record),
        classification_result=classify_registry_record(record),
        sensitive_scan_result=scan_result,
        approval_result=approval_result,
        audit_result=audit_result,
    )


def test_audit_event_creation_is_immutable_and_persisted() -> None:
    record = example_record()
    store = LocalAuditStore()

    result = audit_event(record, store=store)

    assert result.persisted is True
    assert isinstance(result.event, PublicationAuditEvent)
    assert dataclasses.is_dataclass(result.event)
    assert len(store.events) == 1
    assert result.event.evidence_chain_hash.startswith("sha256:")


def test_audit_event_contains_only_allowed_fields() -> None:
    record = example_record()
    result = audit_event(record)
    assert result.event is not None

    assert set(result.event.to_dict()) == {
        "artifact_id",
        "artifact_version",
        "decision",
        "block_reason",
        "policy_version",
        "classification_hash",
        "sensitive_scan_hash",
        "approval_hash",
        "validator_hash",
        "timestamp",
    }


def test_audit_evidence_is_hash_only_and_redacted() -> None:
    record = example_record()
    result = audit_event(record)

    rendered = json.dumps(result.audit.to_dict(), sort_keys=True)

    assert "Approved public governance announcement" not in rendered
    assert "publication-owner" not in rendered
    assert result.audit.evidence_hashes["evidence_chain_hash"].startswith("sha256:")


def test_raw_secret_payload_is_rejected() -> None:
    record = example_record()
    scan_result = scan(record)
    approval_result = approval(record)

    result = create_publication_audit_event(
        record=record,
        decision=PublicationDecision.ALLOW_PUBLICATION,
        block_reason=BlockReason.NONE,
        sensitive_scan_hash=scan_result.audit.evidence_hashes["sensitive_scan_hash"],
        approval_hash=approval_result.audit.evidence_hashes["approval_validation_hash"],
        validator_hash="sha256:example_validator_hash_replace_before_use",
        extra_payload={"debug": "password = never-store-this"},
    )

    assert result.persisted is False
    assert result.block_reason == BlockReason.RAW_SENSITIVE_DATA_PRESENT


def test_missing_evidence_chain_hash_fails_closed() -> None:
    record = example_record()
    approval_result = approval(record)

    result = create_publication_audit_event(
        record=record,
        decision=PublicationDecision.ALLOW_PUBLICATION,
        block_reason=BlockReason.NONE,
        sensitive_scan_hash="",
        approval_hash=approval_result.audit.evidence_hashes["approval_validation_hash"],
        validator_hash="sha256:example_validator_hash_replace_before_use",
    )

    assert result.persisted is False
    assert result.block_reason == BlockReason.EVIDENCE_CHAIN_MISSING


def test_decision_engine_audit_gate_allows_when_audit_present() -> None:
    record = example_record()
    scan_result = scan(record)
    approval_result = approval(record)
    audit_result = create_publication_audit_event(
        record=record,
        decision=PublicationDecision.ALLOW_PUBLICATION,
        block_reason=BlockReason.NONE,
        sensitive_scan_hash=scan_result.audit.evidence_hashes["sensitive_scan_hash"],
        approval_hash=approval_result.audit.evidence_hashes["approval_validation_hash"],
        validator_hash="sha256:example_validator_hash_replace_before_use",
    )
    connector_result = connector(record, scan_result, approval_result, audit_result)

    result = evaluate_publication_decision(
        record,
        sensitive_scan_result=scan_result,
        approval_result=approval_result,
        audit_result=audit_result,
        connector_gate_result=connector_result,
    )

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["evidence_chain_hash"].startswith("sha256:")


def test_decision_engine_missing_audit_evidence_fails_closed() -> None:
    record = example_record()

    result = evaluate_publication_decision(
        record,
        sensitive_scan_result=scan(record),
        approval_result=approval(record),
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.AUDIT_EVIDENCE_MISSING
    assert result.block_reason == BlockReason.AUDIT_EVENT_MISSING
