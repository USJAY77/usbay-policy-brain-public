from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from pathlib import Path

from publication.classification import classify_registry_record
from publication.audit_persistence import create_publication_audit_event
from publication.connector_gate import evaluate_connector_gate
from publication.decision_engine import evaluate_publication_decision
from publication.human_approval import resolve_human_approval
from publication.models import (
    ApprovalEvidence,
    ApprovalState,
    BlockReason,
    ClassificationState,
    LifecycleState,
    PublicationDecision,
    PublicationDecisionResult,
    RegistryRecord,
)
from publication.registry_store import InMemoryRegistryStore, load_json_file, load_registry_record
from publication.registry_validator import validate_registry_record
from publication.sensitive_data_scanner import scan_publication_content
from publication.state_machine import can_transition, transition_lifecycle


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "policy" / "publication" / "publication_registry_schema.json"
RECORD_PATH = ROOT / "policy" / "publication" / "publication_registry_record.example.json"
CLASSIFICATION_POLICY_PATH = ROOT / "policy" / "publication" / "publication_classification_policy.json"
APPROVAL_POLICY_PATH = ROOT / "policy" / "publication" / "publication_approval_policy.json"


def example_record(**overrides: object) -> RegistryRecord:
    data = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
    data.update(overrides)
    return RegistryRecord.from_dict(data)


def approval_for(record: RegistryRecord, **overrides: object):
    data = {
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
    data.update(overrides)
    return resolve_human_approval(
        record=record,
        approvals=[ApprovalEvidence.from_dict(data)],
        policy=load_json_file(APPROVAL_POLICY_PATH),
        now=datetime.fromisoformat("2026-06-25T00:00:00+00:00"),
    )


def audit_for(record: RegistryRecord, scan, approval):
    return create_publication_audit_event(
        record=record,
        decision=PublicationDecision.ALLOW_PUBLICATION,
        block_reason=BlockReason.NONE,
        sensitive_scan_hash=scan.audit.evidence_hashes["sensitive_scan_hash"],
        approval_hash=approval.audit.evidence_hashes["approval_validation_hash"],
        validator_hash="sha256:example_validator_hash_replace_before_use",
    )


def connector_for(record: RegistryRecord, scan, approval, audit):
    return evaluate_connector_gate(
        record=record,
        registry_result=validate_registry_record(record),
        classification_result=classify_registry_record(record),
        sensitive_scan_result=scan,
        approval_result=approval,
        audit_result=audit,
    )


def test_policy_loading_reads_publication_json() -> None:
    policy = load_json_file(CLASSIFICATION_POLICY_PATH)

    assert policy["policy_id"] == "USBAY_PUBLICATION_CLASSIFICATION_POLICY"
    assert "LINKEDIN_APPROVED" in policy["publish_eligible_classes"]


def test_registry_store_loads_example_record() -> None:
    record = load_registry_record(RECORD_PATH)
    store = InMemoryRegistryStore([record])

    loaded = store.get(record.artifact_id)

    assert isinstance(loaded, RegistryRecord)
    assert loaded.artifact_id == "PUB-LINKEDIN-EXAMPLE-001"


def test_registry_store_missing_record_fails_closed() -> None:
    result = InMemoryRegistryStore().get("missing")

    assert isinstance(result, PublicationDecisionResult)
    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.REGISTRY_RECORD_MISSING


def test_registry_validation_accepts_complete_record() -> None:
    schema = load_json_file(SCHEMA_PATH)
    result = validate_registry_record(example_record(), schema=schema, active_policy_version="1.0")

    assert result.publish_allowed is True
    assert result.decision == PublicationDecision.ALLOW_PUBLICATION
    assert result.audit.audit_hash.startswith("sha256:")


def test_registry_validation_blocks_version_mismatch() -> None:
    result = validate_registry_record(example_record(policy_version="0.9"), active_policy_version="1.0")

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.POLICY_VERSION_MISMATCH


def test_registry_validation_blocks_malformed_version() -> None:
    result = validate_registry_record(example_record(version="v1"), active_policy_version="1.0")

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.INVALID_FIELD_VALUE


def test_registry_validation_blocks_hash_mismatch_shape() -> None:
    result = validate_registry_record(example_record(content_hash="not-a-hash"), active_policy_version="1.0")

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.HASH_MISMATCH


def test_registry_validation_blocks_unknown_channel() -> None:
    result = validate_registry_record(example_record(target_channel="UNKNOWN_CHANNEL"), active_policy_version="1.0")

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.CONNECTOR_BLOCKED
    assert result.block_reason == BlockReason.CONNECTOR_TARGET_UNKNOWN


def test_classification_allows_approved_publication_class() -> None:
    policy = load_json_file(CLASSIFICATION_POLICY_PATH)
    result = classify_registry_record(example_record(), policy=policy)

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["classification_hash"].startswith("sha256:")


def test_invalid_classification_fails_closed() -> None:
    result = classify_registry_record(example_record(classification="UNREVIEWED"))

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.NEEDS_RECLASSIFICATION
    assert result.block_reason == BlockReason.CLASSIFICATION_INVALID


def test_draft_classification_is_not_publish_eligible() -> None:
    result = classify_registry_record(example_record(classification=ClassificationState.LINKEDIN_DRAFT.value))

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.CLASSIFICATION_NOT_PUBLISH_ELIGIBLE


def test_lifecycle_allows_expected_transition() -> None:
    assert can_transition(LifecycleState.APPROVED, LifecycleState.PUBLISH_ELIGIBLE)


def test_lifecycle_blocks_invalid_transition() -> None:
    record = example_record(lifecycle_state=LifecycleState.DRAFT.value)
    result = transition_lifecycle(record, LifecycleState.PUBLISHED)

    assert isinstance(result, PublicationDecisionResult)
    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.INVALID_LIFECYCLE_TRANSITION


def test_lifecycle_transition_returns_new_record() -> None:
    record = example_record(lifecycle_state=LifecycleState.APPROVED.value)
    result = transition_lifecycle(record, LifecycleState.PUBLISH_ELIGIBLE)

    assert isinstance(result, RegistryRecord)
    assert result.lifecycle_state == LifecycleState.PUBLISH_ELIGIBLE.value
    assert record.lifecycle_state == LifecycleState.APPROVED.value


def test_decision_engine_allows_complete_local_foundation_record() -> None:
    record = example_record()
    scan = scan_publication_content(artifact_id=record.artifact_id, content="Approved public governance announcement.")
    approval = approval_for(record)
    audit = audit_for(record, scan, approval)
    connector = connector_for(record, scan, approval, audit)
    result = evaluate_publication_decision(
        record,
        registry_schema=load_json_file(SCHEMA_PATH),
        classification_policy=load_json_file(CLASSIFICATION_POLICY_PATH),
        approval_state=ApprovalState.APPROVED,
        sensitive_scan_result=scan,
        approval_result=approval,
        audit_result=audit,
        connector_gate_result=connector,
    )

    assert result.publish_allowed is True
    assert result.decision == PublicationDecision.ALLOW_PUBLICATION
    assert result.block_reason == BlockReason.NONE
    assert result.audit.audit_hash.startswith("sha256:")


def test_decision_engine_blocks_missing_approval() -> None:
    record = example_record()
    scan = scan_publication_content(artifact_id=record.artifact_id, content="Approved public governance announcement.")
    result = evaluate_publication_decision(record, approval_state=ApprovalState.UNDER_REVIEW, sensitive_scan_result=scan)

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.NEEDS_HUMAN_REVIEW
    assert result.block_reason == BlockReason.HUMAN_APPROVAL_MISSING


def test_decision_engine_blocks_expired_approval() -> None:
    record = example_record()
    scan = scan_publication_content(artifact_id=record.artifact_id, content="Approved public governance announcement.")
    approval = approval_for(record)
    audit = audit_for(record, scan, approval)
    result = evaluate_publication_decision(
        record,
        approval_state=ApprovalState.EXPIRED,
        sensitive_scan_result=scan,
        approval_result=approval,
        audit_result=audit,
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.NEEDS_HUMAN_REVIEW
    assert result.block_reason == BlockReason.APPROVAL_EXPIRED


def test_decision_engine_blocks_owner_self_approval() -> None:
    record = example_record(reviewer="publication-owner")
    scan = scan_publication_content(artifact_id=record.artifact_id, content="Approved public governance announcement.")
    approval = approval_for(record, reviewer="publication-owner")
    audit = audit_for(record, scan, approval)

    result = evaluate_publication_decision(
        record,
        approval_state=ApprovalState.APPROVED,
        sensitive_scan_result=scan,
        approval_result=approval,
        audit_result=audit,
    )

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.OWNER_SELF_APPROVAL


def test_decision_engine_blocks_non_eligible_lifecycle() -> None:
    record = example_record(lifecycle_state=LifecycleState.CLASSIFIED.value)
    scan = scan_publication_content(artifact_id=record.artifact_id, content="Approved public governance announcement.")
    approval = approval_for(record)
    audit = audit_for(record, scan, approval)

    result = evaluate_publication_decision(
        record,
        approval_state=ApprovalState.APPROVED,
        sensitive_scan_result=scan,
        approval_result=approval,
        audit_result=audit,
    )

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.INVALID_FIELD_VALUE


def test_block_reason_enum_contains_phase_one_reasons() -> None:
    assert BlockReason.REGISTRY_RECORD_MISSING.value == "REGISTRY_RECORD_MISSING"
    assert BlockReason.CLASSIFICATION_INVALID.value == "CLASSIFICATION_INVALID"
    assert BlockReason.HUMAN_APPROVAL_MISSING.value == "HUMAN_APPROVAL_MISSING"
    assert BlockReason.POLICY_VERSION_MISMATCH.value == "POLICY_VERSION_MISMATCH"
    assert BlockReason.SENSITIVE_SCAN_MISSING.value == "SENSITIVE_SCAN_MISSING"


def test_registry_record_is_immutable() -> None:
    record = example_record()

    assert dataclasses.is_dataclass(record)
    try:
        record.artifact_id = "changed"  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("RegistryRecord must be immutable")
