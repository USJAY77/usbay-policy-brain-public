from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.models import ApprovalEvidence, BlockReason, PublicationDecision, RegistryRecord, hash_payload
from publication.policy_bundle_validator import (
    REQUIRED_POLICY_ORDER,
    load_publication_policy_bundle,
    validate_policy_bundle,
)
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


def test_valid_policy_bundle_passes() -> None:
    result = validate_policy_bundle(bundle())

    assert result.valid is True
    assert result.policy_version == "1.0"
    assert result.bundle_hash.startswith("sha256:")
    assert result.evidence_hash.startswith("sha256:")
    assert result.rejected_policy == ""
    assert result.reason == "POLICY_BUNDLE_VALID"


def test_missing_policy_bundle_fails_closed() -> None:
    result = validate_policy_bundle(None)

    assert result.valid is False
    assert result.reason == "MISSING_POLICY_BUNDLE"
    assert result.rejected_policy == "BUNDLE"


def test_missing_policy_fails_closed() -> None:
    candidate = bundle()
    candidate.pop("approval_policy")

    result = validate_policy_bundle(candidate)

    assert result.valid is False
    assert result.reason == "MISSING_POLICY"
    assert result.rejected_policy == "approval_policy"


def test_duplicate_policy_identifier_fails_closed() -> None:
    candidate = bundle()
    candidate["approval_policy"]["policy_id"] = candidate["classification_policy"]["policy_id"]

    result = validate_policy_bundle(candidate)

    assert result.valid is False
    assert result.reason == "DUPLICATE_POLICY"


def test_policy_order_mismatch_fails_closed() -> None:
    candidate = bundle()
    reordered = {
        "approval_policy": candidate["approval_policy"],
        "registry_schema": candidate["registry_schema"],
        "registry_record": candidate["registry_record"],
        "classification_policy": candidate["classification_policy"],
    }

    result = validate_policy_bundle(reordered)

    assert result.valid is False
    assert result.reason == "POLICY_ORDER_INVALID"


def test_invalid_schema_fails_closed() -> None:
    candidate = bundle()
    candidate["registry_schema"].pop("required")

    result = validate_policy_bundle(candidate)

    assert result.valid is False
    assert result.reason == "MALFORMED_SCHEMA"
    assert result.rejected_policy == "registry_schema"


def test_version_mismatch_fails_closed() -> None:
    candidate = bundle()
    candidate["approval_policy"]["version"] = "0.9"

    result = validate_policy_bundle(candidate)

    assert result.valid is False
    assert result.reason == "VERSION_MISMATCH"
    assert result.rejected_policy == "approval_policy"


def test_hash_mismatch_fails_closed() -> None:
    candidate = bundle()
    expected_hashes = {name: hash_payload(candidate[name]) for name in REQUIRED_POLICY_ORDER}
    expected_hashes["classification_policy"] = "sha256:not_the_expected_hash"

    result = validate_policy_bundle(candidate, expected_hashes=expected_hashes)

    assert result.valid is False
    assert result.reason == "HASH_MISMATCH"
    assert result.rejected_policy == "classification_policy"


def test_unsupported_version_fails_closed() -> None:
    result = validate_policy_bundle(bundle(), supported_version="9.9")

    assert result.valid is False
    assert result.reason == "VERSION_MISMATCH"


def test_dependency_inconsistency_fails_closed() -> None:
    candidate = bundle()
    candidate["registry_record"]["classification"] = "INTERNAL"

    result = validate_policy_bundle(candidate)

    assert result.valid is False
    assert result.reason == "DEPENDENCY_INCONSISTENT"


def test_runtime_aggregator_blocks_missing_policy_bundle_validation() -> None:
    record = example_record()

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
        commit_scope_result=validate_commit_scope(APPROVED_PUBGOV_013_021_FILES),
        policy_bundle_result=None,
        policy_bundle_readiness=evaluate_policy_bundle_readiness(None),
    )

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.BLOCK_PUBLICATION
    assert result.block_reason == BlockReason.POLICY_BUNDLE_NOT_APPROVED
