from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.final_report import generate_final_publication_report
from publication.models import (
    ApprovalEvidence,
    BlockReason,
    FinalPublicationReport,
    PublicationDecision,
    PublicationDecisionResult,
    RegistryRecord,
)
from publication.policy_bundle_validator import load_publication_policy_bundle, validate_policy_bundle
from publication.policy_bundle_readiness import evaluate_policy_bundle_readiness
from publication.registry_store import load_json_file
from publication.runtime_aggregator import aggregate_runtime_publication_decision, aggregate_runtime_publication_report


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "policy" / "publication" / "publication_registry_record.example.json"
SCHEMA_PATH = ROOT / "policy" / "publication" / "publication_registry_schema.json"
CLASSIFICATION_POLICY_PATH = ROOT / "policy" / "publication" / "publication_classification_policy.json"
APPROVAL_POLICY_PATH = ROOT / "policy" / "publication" / "publication_approval_policy.json"
NOW = datetime.fromisoformat("2026-06-25T00:00:00+00:00")
CREATED_AT = "2026-06-25T12:00:00+00:00"


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


def aggregate_kwargs(record: RegistryRecord, **overrides: object) -> dict[str, object]:
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    kwargs: dict[str, object] = {
        "content": "Approved public governance announcement.",
        "approvals": [approval(record)],
        "registry_schema": load_json_file(SCHEMA_PATH),
        "classification_policy": load_json_file(CLASSIFICATION_POLICY_PATH),
        "approval_policy": load_json_file(APPROVAL_POLICY_PATH),
        "commit_scope_result": validate_commit_scope(APPROVED_PUBGOV_013_021_FILES),
        "policy_bundle_result": policy_bundle_result,
        "policy_bundle_readiness": evaluate_policy_bundle_readiness(policy_bundle_result),
        "connector_policy": {
            "policy_version": record.policy_version,
            "allowed_target_channels": [record.target_channel],
        },
        "now": NOW,
    }
    kwargs.update(overrides)
    return kwargs


def test_final_report_generator_outputs_complete_hash_only_report() -> None:
    record = example_record()
    decision = aggregate_runtime_publication_decision(record, **aggregate_kwargs(record))

    report = generate_final_publication_report(
        record=record,
        decision_result=decision,
        created_at=CREATED_AT,
    )

    assert isinstance(report, FinalPublicationReport)
    assert report.report_complete is True
    assert report.final_decision == PublicationDecision.ALLOW_PUBLICATION
    assert report.block_reason == BlockReason.NONE
    assert report.artifact_id == record.artifact_id
    assert report.artifact_version == record.version
    assert report.target_channel == record.target_channel
    assert report.created_at == CREATED_AT
    assert report.evidence_chain_verification_hash.startswith("sha256:")
    assert report.audit_hash.startswith("sha256:")
    assert report.connector_gate_hash.startswith("sha256:")
    assert report.human_approval_hash.startswith("sha256:")
    assert report.sensitive_scan_hash.startswith("sha256:")
    assert report.classification_hash.startswith("sha256:")
    assert report.registry_hash.startswith("sha256:")
    assert report.report_hash.startswith("sha256:")


def test_runtime_aggregator_can_generate_final_report_after_decision() -> None:
    record = example_record()

    report = aggregate_runtime_publication_report(
        record,
        created_at=CREATED_AT,
        **aggregate_kwargs(record),
    )

    assert report.report_complete is True
    assert report.final_decision == PublicationDecision.ALLOW_PUBLICATION
    assert report.evidence_chain_verification_hash.startswith("sha256:")


def test_final_report_blocks_when_required_hash_missing() -> None:
    record = example_record()
    decision = PublicationDecisionResult.allowed(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence_hashes={
            "registry_hash": record.stable_hash(),
            "classification_hash": record.classification_hash,
        },
    )

    report = generate_final_publication_report(
        record=record,
        decision_result=decision,
        created_at=CREATED_AT,
    )

    assert report.report_complete is False
    assert report.final_decision == PublicationDecision.BLOCK_PUBLICATION
    assert report.block_reason == BlockReason.REPORT_INCOMPLETE
    assert report.evidence_chain_verification_hash == ""


def test_final_report_blocks_missing_decision_result() -> None:
    record = example_record()

    report = generate_final_publication_report(
        record=record,
        decision_result=None,
        created_at=CREATED_AT,
    )

    assert report.report_complete is False
    assert report.block_reason == BlockReason.REPORT_INCOMPLETE


def test_final_report_for_blocked_aggregator_is_report_incomplete() -> None:
    record = example_record()
    report = aggregate_runtime_publication_report(
        record,
        content="customer confidential material",
        approvals=[approval(record)],
        registry_schema=load_json_file(SCHEMA_PATH),
        classification_policy=load_json_file(CLASSIFICATION_POLICY_PATH),
        approval_policy=load_json_file(APPROVAL_POLICY_PATH),
        commit_scope_result=validate_commit_scope(APPROVED_PUBGOV_013_021_FILES),
        policy_bundle_result=validate_policy_bundle(load_publication_policy_bundle()),
        policy_bundle_readiness=evaluate_policy_bundle_readiness(validate_policy_bundle(load_publication_policy_bundle())),
        now=NOW,
        created_at=CREATED_AT,
    )

    assert report.report_complete is False
    assert report.final_decision == PublicationDecision.BLOCK_PUBLICATION
    assert report.block_reason == BlockReason.REPORT_INCOMPLETE


def test_final_report_contains_no_raw_artifact_or_sensitive_values() -> None:
    record = example_record()
    report = aggregate_runtime_publication_report(
        record,
        created_at=CREATED_AT,
        **aggregate_kwargs(record),
    )

    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert "Approved public governance announcement" not in rendered
    assert "customer confidential" not in rendered.lower()
    assert "approval_timestamp" not in rendered
    assert "connector_payload" not in rendered
    assert "secret" not in rendered.lower()
