from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.models import (
    ApprovalEvidence,
    BlockReason,
    ClassificationState,
    PublicationDecision,
    RegistryRecord,
)
from publication.policy_bundle_validator import load_publication_policy_bundle, validate_policy_bundle
from publication.policy_bundle_readiness import evaluate_policy_bundle_readiness
from publication.registry_store import load_json_file
from publication.runtime_aggregator import aggregate_runtime_publication_decision


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "policy" / "publication" / "publication_registry_record.example.json"
SCHEMA_PATH = ROOT / "policy" / "publication" / "publication_registry_schema.json"
CLASSIFICATION_POLICY_PATH = ROOT / "policy" / "publication" / "publication_classification_policy.json"
APPROVAL_POLICY_PATH = ROOT / "policy" / "publication" / "publication_approval_policy.json"
NOW = datetime.fromisoformat("2026-06-25T00:00:00+00:00")


def example_record(**overrides: object) -> RegistryRecord:
    data = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
    data.update(overrides)
    return RegistryRecord.from_dict(data)


def approval(record: RegistryRecord, **overrides: object) -> ApprovalEvidence:
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
    return ApprovalEvidence.from_dict(data)


def aggregate(record: RegistryRecord | None, **kwargs):
    policy_bundle_result = kwargs.pop("policy_bundle_result", validate_policy_bundle(load_publication_policy_bundle()))
    return aggregate_runtime_publication_decision(
        record,
        content=kwargs.pop("content", "Approved public governance announcement."),
        approvals=kwargs.pop("approvals", [approval(record)] if record is not None else None),
        registry_schema=kwargs.pop("registry_schema", load_json_file(SCHEMA_PATH)),
        classification_policy=kwargs.pop("classification_policy", load_json_file(CLASSIFICATION_POLICY_PATH)),
        approval_policy=kwargs.pop("approval_policy", load_json_file(APPROVAL_POLICY_PATH)),
        now=kwargs.pop("now", NOW),
        commit_scope_result=kwargs.pop("commit_scope_result", validate_commit_scope(APPROVED_PUBGOV_013_021_FILES)),
        policy_bundle_result=policy_bundle_result,
        policy_bundle_readiness=kwargs.pop(
            "policy_bundle_readiness",
            evaluate_policy_bundle_readiness(policy_bundle_result),
        ),
        **kwargs,
    )


def test_final_runtime_aggregator_allows_complete_local_publication() -> None:
    record = example_record()

    result = aggregate(
        record,
        connector_policy={
            "policy_version": record.policy_version,
            "allowed_target_channels": [record.target_channel],
        },
    )

    assert result.publish_allowed is True
    assert result.decision == PublicationDecision.ALLOW_PUBLICATION
    assert result.block_reason == BlockReason.NONE
    assert result.audit.evidence_hashes["connector_gate_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["evidence_chain_verification_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["finalization_gate_evidence_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["publication_lock_evidence_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["publication_lock_id"].startswith("sha256:")
    assert result.audit.evidence_hashes["publication_lock_release_evidence_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["publication_lock_release_id"].startswith("sha256:")
    assert result.audit.evidence_hashes["publication_release_blocker_evidence_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["publication_release_block_id"].startswith("sha256:")
    assert result.audit.evidence_hashes["release_blocker_integrity_evidence_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["release_blocker_integrity_id"].startswith("sha256:")
    assert result.audit.evidence_hashes["evidence_consistency_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["evidence_seal_hash"].startswith("sha256:")


def test_final_runtime_aggregator_blocks_missing_registry() -> None:
    result = aggregate_runtime_publication_decision(
        None,
        content="Approved public governance announcement.",
        approvals=None,
        commit_scope_result=validate_commit_scope(APPROVED_PUBGOV_013_021_FILES),
        policy_bundle_result=validate_policy_bundle(load_publication_policy_bundle()),
        policy_bundle_readiness=evaluate_policy_bundle_readiness(validate_policy_bundle(load_publication_policy_bundle())),
    )

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.REGISTRY_RECORD_MISSING


def test_final_runtime_aggregator_blocks_missing_classification() -> None:
    result = aggregate(example_record(classification="UNREVIEWED"))

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.BLOCK_PUBLICATION
    assert result.block_reason == BlockReason.CLASSIFICATION_INVALID


def test_final_runtime_aggregator_blocks_non_publishable_classification() -> None:
    result = aggregate(example_record(classification=ClassificationState.LINKEDIN_DRAFT.value))

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.CLASSIFICATION_NOT_PUBLISH_ELIGIBLE


def test_final_runtime_aggregator_blocks_sensitive_data_present() -> None:
    result = aggregate(example_record(), content="customer confidential material")

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.SENSITIVE_DATA_BLOCKED
    assert result.block_reason == BlockReason.SENSITIVE_DATA_PRESENT


def test_final_runtime_aggregator_blocks_missing_human_approval() -> None:
    result = aggregate(example_record(), approvals=None)

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.NEEDS_HUMAN_REVIEW
    assert result.block_reason == BlockReason.HUMAN_APPROVAL_MISSING


def test_final_runtime_aggregator_blocks_expired_human_approval() -> None:
    record = example_record()

    result = aggregate(
        record,
        approvals=[approval(record, approval_state="EXPIRED")],
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.NEEDS_HUMAN_REVIEW
    assert result.block_reason == BlockReason.APPROVAL_EXPIRED


def test_final_runtime_aggregator_blocks_missing_audit_evidence() -> None:
    result = aggregate(example_record(), create_audit=False)

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.AUDIT_EVIDENCE_MISSING
    assert result.block_reason == BlockReason.AUDIT_EVENT_MISSING


def test_final_runtime_aggregator_blocks_connector_gate_failure() -> None:
    record = example_record()

    result = aggregate(
        record,
        connector_policy={
            "policy_version": record.policy_version,
            "allowed_target_channels": ["PAGES"],
        },
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.CONNECTOR_BLOCKED
    assert result.block_reason == BlockReason.CONNECTOR_TARGET_UNKNOWN


def test_final_runtime_aggregator_blocks_policy_mismatch() -> None:
    record = example_record()

    result = aggregate(
        record,
        connector_policy={
            "policy_version": "0.0.0",
            "allowed_target_channels": [record.target_channel],
        },
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.CONNECTOR_BLOCKED
    assert result.block_reason == BlockReason.POLICY_VERSION_MISMATCH


def test_final_runtime_aggregator_blocks_unknown_target_channel() -> None:
    result = aggregate(example_record(target_channel="UNKNOWN_CHANNEL"))

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.CONNECTOR_BLOCKED
    assert result.block_reason == BlockReason.CONNECTOR_TARGET_UNKNOWN


def test_final_runtime_aggregator_blocks_attempted_automatic_publication() -> None:
    result = aggregate(example_record(), automatic_publication_requested=True)

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.CONNECTOR_BLOCKED
    assert result.block_reason == BlockReason.AUTO_PUBLICATION_FORBIDDEN


def test_final_runtime_aggregator_blocks_missing_commit_scope_approval() -> None:
    result = aggregate(example_record(), commit_scope_result=None)

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.BLOCK_PUBLICATION
    assert result.block_reason == BlockReason.COMMIT_SCOPE_NOT_APPROVED


def test_final_runtime_aggregator_blocks_missing_policy_bundle_validation() -> None:
    result = aggregate(example_record(), policy_bundle_result=None)

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.BLOCK_PUBLICATION
    assert result.block_reason == BlockReason.POLICY_BUNDLE_NOT_APPROVED


def test_final_runtime_aggregator_blocks_missing_policy_bundle_readiness() -> None:
    result = aggregate(example_record(), policy_bundle_readiness=None)

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.BLOCK_PUBLICATION
    assert result.block_reason == BlockReason.POLICY_BUNDLE_NOT_APPROVED
