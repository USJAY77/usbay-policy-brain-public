from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from publication.audit_persistence import create_publication_audit_event
from publication.classification import classify_registry_record
from publication.connector_gate import (
    ConnectorGateValidator,
    allowed_channels_from_policy,
    evaluate_connector_gate,
)
from publication.decision_engine import evaluate_publication_decision
from publication.human_approval import resolve_human_approval
from publication.models import (
    ApprovalEvidence,
    BlockReason,
    ConnectorEligibilityResult,
    ConnectorGateDecision,
    PublicationDecision,
    PublicationDecisionResult,
    RegistryRecord,
)
from publication.registry_validator import validate_registry_record
from publication.registry_store import load_json_file
from publication.sensitive_data_scanner import scan_publication_content


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "policy" / "publication" / "publication_registry_record.example.json"
APPROVAL_POLICY_PATH = ROOT / "policy" / "publication" / "publication_approval_policy.json"
NOW = datetime.fromisoformat("2026-06-25T00:00:00+00:00")


def example_record(**overrides: object) -> RegistryRecord:
    data = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
    data.update(overrides)
    return RegistryRecord.from_dict(data)


def approval(record: RegistryRecord, **overrides: object):
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
        now=NOW,
    )


def clean_scan(record: RegistryRecord):
    return scan_publication_content(
        artifact_id=record.artifact_id,
        content="Approved public governance announcement.",
    )


def failed_scan(record: RegistryRecord):
    return scan_publication_content(
        artifact_id=record.artifact_id,
        content="customer confidential material",
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


def connector_for(record: RegistryRecord, scan, approval_result, audit_result, **kwargs):
    return evaluate_connector_gate(
        record=record,
        registry_result=validate_registry_record(record),
        classification_result=classify_registry_record(record),
        sensitive_scan_result=scan,
        approval_result=approval_result,
        audit_result=audit_result,
        **kwargs,
    )


def test_connector_gate_allow_path() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = connector_for(record, scan, approval_result, audit_result)

    assert isinstance(result, ConnectorEligibilityResult)
    assert result.publish_allowed is True
    assert result.gate_decision == ConnectorGateDecision.CONNECTOR_GATE_ALLOWED
    assert result.block_reason == BlockReason.NONE
    assert result.audit.evidence_hashes["connector_gate_hash"].startswith("sha256:")
    assert result.evidence["raw_content_stored"] is False


def test_unknown_channel_blocked() -> None:
    record = example_record(target_channel="UNKNOWN_CHANNEL")
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = connector_for(record, scan, approval_result, audit_result)

    assert result.publish_allowed is False
    assert result.gate_decision == ConnectorGateDecision.CONNECTOR_GATE_BLOCKED
    assert result.block_reason == BlockReason.CONNECTOR_TARGET_UNKNOWN


def test_policy_unknown_connector_blocked() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = connector_for(
        record,
        scan,
        approval_result,
        audit_result,
        connector_policy={
            "policy_version": record.policy_version,
            "allowed_target_channels": ["PAGES"],
        },
    )

    assert allowed_channels_from_policy({"allowed_target_channels": ["PAGES"]}) == {"PAGES"}
    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.CONNECTOR_TARGET_UNKNOWN


def test_policy_mismatch_blocked() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = connector_for(
        record,
        scan,
        approval_result,
        audit_result,
        connector_policy={
            "policy_version": "0.0.0",
            "allowed_target_channels": [record.target_channel],
        },
    )

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.POLICY_VERSION_MISMATCH


def test_malformed_policy_fails_closed() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = connector_for(
        record,
        scan,
        approval_result,
        audit_result,
        connector_policy={
            "policy_version": record.policy_version,
            "allowed_target_channels": "LINKEDIN",
        },
    )

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.INVALID_FIELD_VALUE


def test_missing_audit_evidence_blocked() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = create_publication_audit_event(
        record=record,
        decision=PublicationDecision.ALLOW_PUBLICATION,
        block_reason=BlockReason.NONE,
        sensitive_scan_hash=scan.audit.evidence_hashes["sensitive_scan_hash"],
        approval_hash=approval_result.audit.evidence_hashes["approval_validation_hash"],
        validator_hash="",
    )

    result = connector_for(record, scan, approval_result, audit_result)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.EVIDENCE_CHAIN_MISSING


def test_missing_audit_result_blocked() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)

    result = connector_for(record, scan, approval_result, None)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.AUDIT_EVENT_MISSING


def test_missing_approval_blocked() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record, approval_hash="")
    audit_result = audit_for(record, scan, approval(record))

    result = connector_for(record, scan, approval_result, audit_result)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.MISSING_APPROVAL_EVIDENCE


def test_missing_approval_result_blocked() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = connector_for(record, scan, None, audit_result)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.HUMAN_APPROVAL_MISSING


def test_missing_sensitive_scan_blocked() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = connector_for(record, None, approval_result, audit_result)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.SENSITIVE_SCAN_MISSING


def test_missing_registry_validator_result_blocked() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = evaluate_connector_gate(
        record=record,
        registry_result=None,
        classification_result=classify_registry_record(record),
        sensitive_scan_result=scan,
        approval_result=approval_result,
        audit_result=audit_result,
    )

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.VALIDATOR_RESULT_MISSING


def test_mismatched_sensitive_scan_artifact_blocked() -> None:
    record = example_record()
    other_record = example_record(artifact_id="pub-artifact-other")
    scan = clean_scan(other_record)
    approval_result = approval(record)
    audit_result = audit_for(record, clean_scan(record), approval_result)

    result = connector_for(record, scan, approval_result, audit_result)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.INVALID_SCAN_INPUT


def test_sensitive_scan_failure_blocked() -> None:
    record = example_record()
    scan = failed_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, clean_scan(record), approval_result)

    result = connector_for(record, scan, approval_result, audit_result)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.SENSITIVE_DATA_PRESENT


def test_automatic_publication_blocked() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = connector_for(
        record,
        scan,
        approval_result,
        audit_result,
        automatic_publication_requested=True,
    )

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.AUTO_PUBLICATION_FORBIDDEN


def test_publication_lock_blocks_connector_gate() -> None:
    record = example_record(lifecycle_state="BLOCKED")
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = connector_for(record, scan, approval_result, audit_result)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.INVALID_FIELD_VALUE


def test_blocked_publication_state_blocks_connector_gate() -> None:
    record = example_record(classification="LINKEDIN_DRAFT")
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = connector_for(record, scan, approval_result, audit_result)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.CLASSIFICATION_NOT_PUBLISH_ELIGIBLE


def test_connector_gate_validator_allows_only_valid_policy_scope() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)
    validator = ConnectorGateValidator(
        connector_policy={
            "policy_version": record.policy_version,
            "allowed_target_channels": [record.target_channel],
        }
    )

    result = validator.validate(
        record=record,
        registry_result=validate_registry_record(record),
        classification_result=classify_registry_record(record),
        sensitive_scan_result=scan,
        approval_result=approval_result,
        audit_result=audit_result,
    )

    assert result.publish_allowed is True
    assert result.gate_decision == ConnectorGateDecision.CONNECTOR_GATE_ALLOWED


def test_decision_engine_blocks_missing_connector_gate() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)

    result = evaluate_publication_decision(
        record,
        sensitive_scan_result=scan,
        approval_result=approval_result,
        audit_result=audit_result,
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.CONNECTOR_BLOCKED
    assert result.block_reason == BlockReason.CONNECTOR_GATE_MISSING


def test_decision_engine_allows_with_connector_gate() -> None:
    record = example_record()
    scan = clean_scan(record)
    approval_result = approval(record)
    audit_result = audit_for(record, scan, approval_result)
    connector_result = connector_for(record, scan, approval_result, audit_result)

    result = evaluate_publication_decision(
        record,
        sensitive_scan_result=scan,
        approval_result=approval_result,
        audit_result=audit_result,
        connector_gate_result=connector_result,
    )

    assert result.publish_allowed is True
    assert result.decision == PublicationDecision.ALLOW_PUBLICATION
    assert result.audit.evidence_hashes["connector_gate_hash"].startswith("sha256:")
