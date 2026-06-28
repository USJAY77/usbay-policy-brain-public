from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.models import ApprovalEvidence, BlockReason, PublicationDecision, RegistryRecord
from publication.policy_bundle_validator import load_publication_policy_bundle, validate_policy_bundle
from publication.policy_bundle_readiness import evaluate_policy_bundle_readiness
from publication.registry_store import load_json_file
from publication.runtime_aggregator import aggregate_runtime_publication_decision
from publication.staging_manifest import generate_staging_manifest, staging_manifest_json


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


def test_clean_allowlist_passes() -> None:
    result = validate_commit_scope(APPROVED_PUBGOV_013_021_FILES)

    assert result.approved is True
    assert result.rejected_files == ()
    assert result.staged_files == APPROVED_PUBGOV_013_021_FILES
    assert result.evidence_hash.startswith("sha256:")
    assert result.policy_version == "USBAY-PUBGOV-024"
    assert result.reason == "APPROVED_SCOPE"


def test_forbidden_file_fails_closed() -> None:
    result = validate_commit_scope(("docs/audits/ENFORCEMENT_AUDIT.md",))

    assert result.approved is False
    assert result.rejected_files == ("docs/audits/ENFORCEMENT_AUDIT.md",)
    assert result.reason == "FORBIDDEN_OR_UNAPPROVED_FILES"


def test_mixed_files_fail_closed() -> None:
    result = validate_commit_scope(
        (
            "publication/models.py",
            "gateway/app.py",
        )
    )

    assert result.approved is False
    assert result.staged_files == ("publication/models.py",)
    assert result.rejected_files == ("gateway/app.py",)


def test_duplicate_files_are_handled_deterministically() -> None:
    result = validate_commit_scope(
        (
            "publication/models.py",
            "./publication/models.py",
            "tests/test_publication_runtime_foundation.py",
        )
    )

    assert result.approved is True
    assert result.staged_files == (
        "publication/models.py",
        "tests/test_publication_runtime_foundation.py",
    )
    assert result.rejected_files == ()


def test_empty_candidate_list_fails_closed() -> None:
    result = validate_commit_scope(())

    assert result.approved is False
    assert result.reason == "EMPTY_CANDIDATE_LIST"
    assert result.evidence_hash.startswith("sha256:")


def test_staging_manifest_contains_only_approved_files() -> None:
    manifest = generate_staging_manifest(("publication/models.py", "tests/test_publication_runtime_foundation.py"))

    assert manifest["approved"] is True
    assert manifest["staged_files"] == ("publication/models.py", "tests/test_publication_runtime_foundation.py")
    assert manifest["rejected_files"] == ()
    assert manifest["scope_evidence_hash"].startswith("sha256:")
    assert manifest["manifest_hash"].startswith("sha256:")
    assert manifest["raw_file_content_stored"] is False


def test_staging_manifest_json_is_deterministic_json() -> None:
    rendered = staging_manifest_json(("publication/models.py",))
    parsed = json.loads(rendered)

    assert parsed["approved"] is True
    assert parsed["staged_files"] == ["publication/models.py"]
    assert parsed["manifest_hash"].startswith("sha256:")


def test_unrelated_test_file_fails_closed() -> None:
    result = validate_commit_scope(("tests/test_runtime_governance_state.py",))

    assert result.approved is False
    assert result.rejected_files == ("tests/test_runtime_governance_state.py",)


def test_runtime_aggregator_blocks_rejected_commit_scope() -> None:
    record = example_record()
    rejected_scope = validate_commit_scope(("publication/models.py", "docs/game/USBAY_GAME_VISION.md"))

    result = aggregate_runtime_publication_decision(
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
        commit_scope_result=rejected_scope,
        policy_bundle_result=validate_policy_bundle(load_publication_policy_bundle()),
        policy_bundle_readiness=evaluate_policy_bundle_readiness(validate_policy_bundle(load_publication_policy_bundle())),
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.BLOCK_PUBLICATION
    assert result.block_reason == BlockReason.COMMIT_SCOPE_NOT_APPROVED
    assert result.audit.evidence_hashes["commit_scope_evidence_hash"] == rejected_scope.evidence_hash
