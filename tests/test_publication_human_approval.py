from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from publication.audit_persistence import create_publication_audit_event
from publication.classification import classify_registry_record
from publication.connector_gate import evaluate_connector_gate
from publication.decision_engine import evaluate_publication_decision
from publication.human_approval import resolve_human_approval
from publication.models import (
    ApprovalEvidence,
    ApprovalState,
    BlockReason,
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


def approval_policy() -> dict:
    return load_json_file(APPROVAL_POLICY_PATH)


def clean_scan(record: RegistryRecord):
    return scan_publication_content(
        artifact_id=record.artifact_id,
        content="Approved public governance announcement.",
    )


def audit_for(record: RegistryRecord, scan, approval_result):
    return create_publication_audit_event(
        record=record,
        decision=PublicationDecision.ALLOW_PUBLICATION,
        block_reason=BlockReason.NONE,
        sensitive_scan_hash=scan.audit.evidence_hashes["sensitive_scan_hash"],
        approval_hash=approval_result.audit.evidence_hashes["approval_validation_hash"],
        validator_hash="sha256:example_validator_hash_replace_before_use",
    )


def connector_for(record: RegistryRecord, scan, approval_result, audit_result):
    return evaluate_connector_gate(
        record=record,
        registry_result=validate_registry_record(record),
        classification_result=classify_registry_record(record),
        sensitive_scan_result=scan,
        approval_result=approval_result,
        audit_result=audit_result,
    )


def test_valid_approval_passes_with_hash_only_evidence() -> None:
    record = example_record()
    result = resolve_human_approval(
        record=record,
        approvals=[approval(record)],
        policy=approval_policy(),
        now=NOW,
    )

    evidence_text = json.dumps(result.evidence, sort_keys=True)
    assert result.passed is True
    assert result.block_reason == BlockReason.NONE
    assert result.audit.audit_hash.startswith("sha256:")
    assert "approval_reason" not in evidence_text
    assert result.evidence["raw_approval_content_stored"] is False


def test_missing_approval_fails_closed() -> None:
    record = example_record()

    result = resolve_human_approval(record=record, approvals=None, policy=approval_policy(), now=NOW)

    assert result.passed is False
    assert result.block_reason == BlockReason.HUMAN_APPROVAL_MISSING


def test_expired_approval_fails_closed() -> None:
    record = example_record()

    result = resolve_human_approval(
        record=record,
        approvals=[approval(record, approval_timestamp="2020-01-01T00:00:00Z")],
        policy=approval_policy(),
        now=NOW,
        approval_ttl_days=30,
    )

    assert result.passed is False
    assert result.block_reason == BlockReason.APPROVAL_EXPIRED


def test_invalid_reviewer_role_fails_closed() -> None:
    record = example_record()

    result = resolve_human_approval(
        record=record,
        approvals=[approval(record, reviewer_role="Pricing Reviewer")],
        policy=approval_policy(),
        now=NOW,
    )

    assert result.passed is False
    assert result.block_reason == BlockReason.REVIEWER_AUTHORITY_MISSING


def test_self_approval_is_blocked() -> None:
    record = example_record(reviewer="publication-owner")

    result = resolve_human_approval(
        record=record,
        approvals=[approval(record, reviewer="publication-owner")],
        policy=approval_policy(),
        now=NOW,
    )

    assert result.passed is False
    assert result.block_reason == BlockReason.OWNER_SELF_APPROVAL


def test_required_multi_review_missing_fails_closed() -> None:
    record = example_record()

    result = resolve_human_approval(
        record=record,
        approvals=[approval(record, reviewer_role="Publication Reviewer")],
        policy=approval_policy(),
        required_roles=("Publication Reviewer", "Governance Reviewer"),
        now=NOW,
    )

    assert result.passed is False
    assert result.block_reason == BlockReason.REQUIRED_MULTI_REVIEW_MISSING
    assert result.evidence["missing_required_roles"] == ("Governance Reviewer",)


def test_required_multi_review_passes_when_all_roles_present() -> None:
    record = example_record()
    approvals = [
        approval(record, reviewer="publication-reviewer", reviewer_role="Publication Reviewer"),
        approval(record, reviewer="governance-reviewer", reviewer_role="Governance Reviewer"),
    ]

    result = resolve_human_approval(
        record=record,
        approvals=approvals,
        policy=approval_policy(),
        required_roles=("Publication Reviewer", "Governance Reviewer"),
        now=NOW,
    )

    assert result.passed is True
    assert result.reviewer_references == ("governance-reviewer", "publication-reviewer")


def test_missing_approval_evidence_fails_closed() -> None:
    record = example_record()

    result = resolve_human_approval(
        record=record,
        approvals=[approval(record, approval_hash="")],
        policy=approval_policy(),
        now=NOW,
    )

    assert result.passed is False
    assert result.block_reason == BlockReason.MISSING_APPROVAL_EVIDENCE


def test_decision_engine_blocks_without_approval_result() -> None:
    record = example_record()

    result = evaluate_publication_decision(
        record,
        approval_state=ApprovalState.APPROVED,
        sensitive_scan_result=clean_scan(record),
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.NEEDS_HUMAN_REVIEW
    assert result.block_reason == BlockReason.HUMAN_APPROVAL_MISSING


def test_decision_engine_blocks_failed_approval_result() -> None:
    record = example_record()
    approval_result = resolve_human_approval(
        record=record,
        approvals=[approval(record, reviewer_role="Pricing Reviewer")],
        policy=approval_policy(),
        now=NOW,
    )

    result = evaluate_publication_decision(
        record,
        sensitive_scan_result=clean_scan(record),
        approval_result=approval_result,
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.NEEDS_HUMAN_REVIEW
    assert result.block_reason == BlockReason.REVIEWER_AUTHORITY_MISSING


def test_decision_engine_allows_valid_approval_and_clean_scan() -> None:
    record = example_record()
    approval_result = resolve_human_approval(
        record=record,
        approvals=[approval(record)],
        policy=approval_policy(),
        now=NOW,
    )

    scan = clean_scan(record)
    audit = audit_for(record, scan, approval_result)
    connector = connector_for(record, scan, approval_result, audit)
    result = evaluate_publication_decision(
        record,
        sensitive_scan_result=scan,
        approval_result=approval_result,
        audit_result=audit,
        connector_gate_result=connector,
    )

    assert result.publish_allowed is True
    assert result.decision == PublicationDecision.ALLOW_PUBLICATION
    assert result.audit.evidence_hashes["approval_validation_hash"].startswith("sha256:")


def test_decision_engine_blocks_without_audit_result() -> None:
    record = example_record()
    approval_result = resolve_human_approval(
        record=record,
        approvals=[approval(record)],
        policy=approval_policy(),
        now=NOW,
    )

    result = evaluate_publication_decision(
        record,
        sensitive_scan_result=clean_scan(record),
        approval_result=approval_result,
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.AUDIT_EVIDENCE_MISSING
    assert result.block_reason == BlockReason.AUDIT_EVENT_MISSING
