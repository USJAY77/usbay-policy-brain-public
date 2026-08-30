from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.models import ApprovalEvidence, BlockReason, PublicationDecision, RegistryRecord, hash_payload
from publication.policy_bundle_readiness import REQUIRED_POLICY_IDS, evaluate_policy_bundle_readiness
from publication.policy_bundle_validator import (
    REQUIRED_POLICY_ORDER,
    load_publication_policy_bundle,
    validate_policy_bundle,
)
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


def approval(record: RegistryRecord) -> ApprovalEvidence:
    return ApprovalEvidence.from_dict(
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


def bundle() -> dict[str, dict]:
    return copy.deepcopy(load_publication_policy_bundle())


def aggregate(record: RegistryRecord, readiness):
    validation = validate_policy_bundle(load_publication_policy_bundle())
    return aggregate_runtime_publication_decision(
        record,
        content="Approved public governance announcement.",
        approvals=[approval(record)],
        registry_schema=load_json_file(SCHEMA_PATH),
        classification_policy=load_json_file(CLASSIFICATION_POLICY_PATH),
        approval_policy=load_json_file(APPROVAL_POLICY_PATH),
        connector_policy={
            "policy_version": record.policy_version,
            "allowed_target_channels": [record.target_channel],
        },
        now=NOW,
        commit_scope_result=validate_commit_scope(APPROVED_PUBGOV_013_021_FILES),
        policy_bundle_result=validation,
        policy_bundle_readiness=readiness,
    )


def test_valid_bundle_readiness_passes() -> None:
    validation = validate_policy_bundle(bundle())

    readiness = evaluate_policy_bundle_readiness(validation)

    assert readiness.ready is True
    assert readiness.decision == PublicationDecision.ALLOW_PUBLICATION
    assert readiness.block_reason == BlockReason.NONE
    assert readiness.required_policy_ids == REQUIRED_POLICY_IDS
    assert readiness.missing_policy_ids == ()
    assert readiness.invalid_policy_ids == ()
    assert readiness.evidence_hash.startswith("sha256:")
    assert readiness.policy_version == "1.0"


def test_missing_bundle_readiness_fails() -> None:
    readiness = evaluate_policy_bundle_readiness(None)

    assert readiness.ready is False
    assert readiness.block_reason == BlockReason.POLICY_BUNDLE_NOT_APPROVED
    assert readiness.missing_policy_ids == REQUIRED_POLICY_IDS
    assert readiness.invalid_policy_ids == ()


def test_missing_policy_readiness_fails() -> None:
    candidate = bundle()
    candidate.pop("approval_policy")
    validation = validate_policy_bundle(candidate)

    readiness = evaluate_policy_bundle_readiness(validation)

    assert readiness.ready is False
    assert "USBAY_PUBLICATION_APPROVAL_POLICY" in readiness.missing_policy_ids


def test_invalid_policy_readiness_fails() -> None:
    candidate = bundle()
    candidate["registry_schema"].pop("required")
    validation = validate_policy_bundle(candidate)

    readiness = evaluate_policy_bundle_readiness(validation)

    assert readiness.ready is False
    assert "https://usbay.local/policy/publication/publication_registry_schema.json" in readiness.invalid_policy_ids


def test_duplicate_policy_readiness_fails() -> None:
    candidate = bundle()
    candidate["approval_policy"]["policy_id"] = candidate["classification_policy"]["policy_id"]
    validation = validate_policy_bundle(candidate)

    readiness = evaluate_policy_bundle_readiness(validation)

    assert readiness.ready is False
    assert readiness.invalid_policy_ids == REQUIRED_POLICY_IDS


def test_unsupported_version_readiness_fails() -> None:
    validation = validate_policy_bundle(bundle(), supported_version="9.9")

    readiness = evaluate_policy_bundle_readiness(validation)

    assert readiness.ready is False
    assert readiness.invalid_policy_ids


def test_dependency_inconsistency_readiness_fails() -> None:
    candidate = bundle()
    candidate["registry_record"]["classification"] = "INTERNAL"
    validation = validate_policy_bundle(candidate)

    readiness = evaluate_policy_bundle_readiness(validation)

    assert readiness.ready is False
    assert "USBAY_PUBLICATION_CLASSIFICATION_POLICY" in readiness.invalid_policy_ids


def test_runtime_aggregator_blocks_missing_readiness() -> None:
    record = example_record()

    result = aggregate(record, None)

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.BLOCK_PUBLICATION
    assert result.block_reason == BlockReason.POLICY_BUNDLE_NOT_APPROVED


def test_runtime_aggregator_allows_only_with_readiness_true() -> None:
    record = example_record()
    validation = validate_policy_bundle(load_publication_policy_bundle())
    readiness = evaluate_policy_bundle_readiness(validation)

    result = aggregate(record, readiness)

    assert result.publish_allowed is True
    assert result.decision == PublicationDecision.ALLOW_PUBLICATION
    assert result.audit.evidence_hashes["policy_bundle_readiness_evidence_hash"] == readiness.evidence_hash


def test_readiness_evidence_hash_is_deterministic() -> None:
    validation = validate_policy_bundle(bundle())

    first = evaluate_policy_bundle_readiness(validation)
    second = evaluate_policy_bundle_readiness(validation)

    assert first.evidence_hash == second.evidence_hash
    assert first.to_dict() == second.to_dict()


def test_hash_mismatch_readiness_fails() -> None:
    candidate = bundle()
    expected_hashes = {name: hash_payload(candidate[name]) for name in REQUIRED_POLICY_ORDER}
    expected_hashes["approval_policy"] = "sha256:not_the_expected_hash"
    validation = validate_policy_bundle(candidate, expected_hashes=expected_hashes)

    readiness = evaluate_policy_bundle_readiness(validation)

    assert readiness.ready is False
    assert "USBAY_PUBLICATION_APPROVAL_POLICY" in readiness.invalid_policy_ids
