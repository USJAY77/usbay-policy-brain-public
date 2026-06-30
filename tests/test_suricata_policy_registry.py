from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.models import ApprovalEvidence, BlockReason, RegistryRecord, hash_payload
from publication.policy_bundle_readiness import evaluate_policy_bundle_readiness
from publication.policy_bundle_validator import load_publication_policy_bundle, validate_policy_bundle
from publication.registry_store import load_json_file
from publication.runtime_aggregator import aggregate_runtime_publication_decision
from publication.suricata_evidence_adapter import evaluate_suricata_eve_json
from publication.suricata_policy_gate import evaluate_suricata_policy_gate
from publication.suricata_policy_manifest import suricata_policy_evidence_hash
from publication.suricata_policy_registry import SuricataPolicyRegistry
from publication.suricata_rule_signature import expected_rule_signature_hash, verify_suricata_rule_signature
from publication.suricata_rule_source_registry import SuricataRuleSourceRecord, SuricataRuleSourceRegistry
from publication.suricata_trust_anchor_store import SuricataTrustAnchorStore, finalize_suricata_trust_anchor, suricata_trust_anchor_record_hash
from test_suricata_external_signing_authority import signing_authority_result


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "policy" / "publication" / "publication_registry_record.example.json"
SCHEMA_PATH = ROOT / "policy" / "publication" / "publication_registry_schema.json"
CLASSIFICATION_POLICY_PATH = ROOT / "policy" / "publication" / "publication_classification_policy.json"
APPROVAL_POLICY_PATH = ROOT / "policy" / "publication" / "publication_approval_policy.json"
NOW = datetime.fromisoformat("2026-06-25T00:00:00+00:00")
SURICATA_NOW = datetime.fromisoformat("2026-06-27T00:00:00+00:00")


def example_record() -> RegistryRecord:
    return RegistryRecord.from_dict(json.loads(RECORD_PATH.read_text(encoding="utf-8")))


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


def registry_record(**overrides: object) -> dict[str, object]:
    signature_hash = str(overrides.pop("signature_hash", hash_payload("signed-suricata-ruleset-v1")))
    policy_id = str(overrides.pop("policy_id", "suricata-managed-rules"))
    policy_version = str(overrides.pop("policy_version", "2026.06.27"))
    rule_count = int(overrides.pop("rule_count", 42))
    record: dict[str, object] = {
        "policy_id": policy_id,
        "policy_version": policy_version,
        "signature_hash": signature_hash,
        "evidence_hash": suricata_policy_evidence_hash(
            policy_id=policy_id,
            policy_version=policy_version,
            signature_hash=signature_hash,
            rule_count=rule_count,
        ),
        "rule_count": rule_count,
        "created_at": "2026-06-26T00:00:00Z",
        "approved_by": "governance-reviewer",
        "approval_timestamp": "2026-06-26T01:00:00Z",
        "active": True,
        "revoked": False,
    }
    record.update(overrides)
    return record


def valid_registry_result():
    return SuricataPolicyRegistry.from_dicts([registry_record()]).validate(
        policy_id="suricata-managed-rules",
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )


def rule_source_record() -> dict[str, object]:
    return {
        "approved_source_id": "suricata-source-managed",
        "source_name": "Managed Suricata Rules",
        "source_uri_hash": hash_payload("https://rules.invalid/suricata"),
        "approved_public_key_hash": hash_payload("suricata-public-key"),
        "approved_policy_version": "2026.06.27",
        "max_age_seconds": 86400,
        "revoked": False,
        "human_approval_id": "approval-suricata-source-001",
    }


def trust_anchor_result():
    fingerprint = hash_payload("suricata-public-key")
    record = {
        "anchor_id": "suricata-anchor-managed",
        "issuer": "USBAY Suricata Governance",
        "public_key_fingerprint": fingerprint,
        "status": "approved",
        "approved_by_human": True,
        "policy_version": "2026.06.27",
        "created_at": "2026-06-26T00:00:00Z",
        "evidence_hash": suricata_trust_anchor_record_hash(
            anchor_id="suricata-anchor-managed",
            issuer="USBAY Suricata Governance",
            public_key_fingerprint=fingerprint,
            status="approved",
            approved_by_human=True,
            policy_version="2026.06.27",
            created_at="2026-06-26T00:00:00Z",
        ),
    }
    return SuricataTrustAnchorStore([record]).validate_anchor(
        anchor_id="suricata-anchor-managed",
        expected_fingerprint=fingerprint,
        policy_version="2026.06.27",
    )


def trust_anchor_finalizer_result():
    return finalize_suricata_trust_anchor(trust_anchor_result())


def rule_source_result():
    source = rule_source_record()
    public_key_hash = hash_payload("suricata-public-key")
    rule_bundle_hash = hash_payload("local-rule-bundle")
    registry = SuricataRuleSourceRegistry([source]).validate_source(
        approved_source_id="suricata-source-managed",
        policy_version="2026.06.27",
    )
    return verify_suricata_rule_signature(
        metadata={
            "approved_source_id": "suricata-source-managed",
            "policy_version": "2026.06.27",
            "rule_bundle_hash": rule_bundle_hash,
            "public_key_hash": public_key_hash,
            "signature_hash": expected_rule_signature_hash(
                rule_bundle_hash=rule_bundle_hash,
                public_key_hash=public_key_hash,
                policy_version="2026.06.27",
            ),
            "generated_at": "2026-06-26T12:00:00Z",
            "rule_count": 42,
        },
        source_record=SuricataRuleSourceRecord.from_dict(source),
        source_registry_result=registry,
        now=SURICATA_NOW,
    )


def suricata_chain():
    evidence = evaluate_suricata_eve_json(
        {
            "event_type": "alert",
            "alert": {"severity": 1, "signature": "Low", "category": "Policy"},
            "src_ip": "192.0.2.10",
            "dest_ip": "198.51.100.20",
            "payload": "payload-bytes",
        },
        threshold=0,
    )
    gate = evaluate_suricata_policy_gate(
        evidence,
        {"policy_version": "USBAY-SURICATA-002", "severity_threshold": 2, "action_on_threshold_exceeded": "BLOCK"},
    )
    return evidence, gate, valid_registry_result()


def aggregate_with_registry(registry_result):
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, gate, _ = suricata_chain()
    return aggregate_runtime_publication_decision(
        record,
        content="Approved public governance announcement.",
        approvals=[approval(record)],
        registry_schema=load_json_file(SCHEMA_PATH),
        classification_policy=load_json_file(CLASSIFICATION_POLICY_PATH),
        approval_policy=load_json_file(APPROVAL_POLICY_PATH),
        connector_policy={"policy_version": record.policy_version, "allowed_target_channels": [record.target_channel]},
        now=NOW,
        commit_scope_result=validate_commit_scope(APPROVED_PUBGOV_013_021_FILES),
        policy_bundle_result=policy_bundle_result,
        policy_bundle_readiness=evaluate_policy_bundle_readiness(policy_bundle_result),
        suricata_evidence=evidence,
        suricata_policy_gate=gate,
        suricata_policy_registry=registry_result,
        suricata_rule_source=rule_source_result(),
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
    )


def test_valid_registry_passes() -> None:
    result = valid_registry_result()

    assert result.approved is True
    assert result.reason == "SURICATA_POLICY_REGISTRY_APPROVED"
    assert result.evidence_hash.startswith("sha256:")
    assert result.registry_hash.startswith("sha256:")


def test_revoked_registry_fails() -> None:
    result = SuricataPolicyRegistry.from_dicts([registry_record(revoked=True)]).validate(
        policy_id="suricata-managed-rules",
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )

    assert result.approved is False
    assert result.reason == "SURICATA_POLICY_REVOKED"


def test_unsigned_registry_fails() -> None:
    record = registry_record(signature_hash="not-a-hash")
    record["evidence_hash"] = "sha256:bad"

    result = SuricataPolicyRegistry.from_dicts([record]).validate(
        policy_id="suricata-managed-rules",
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )

    assert result.approved is False
    assert result.reason == "SURICATA_POLICY_UNSIGNED"


def test_duplicate_registry_version_fails() -> None:
    result = SuricataPolicyRegistry.from_dicts([registry_record(), registry_record()]).validate(
        policy_id="suricata-managed-rules",
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )

    assert result.approved is False
    assert result.reason == "SURICATA_POLICY_DUPLICATE_VERSION"


def test_stale_registry_fails() -> None:
    result = SuricataPolicyRegistry.from_dicts([registry_record(approval_timestamp="2024-01-01T00:00:00Z")]).validate(
        policy_id="suricata-managed-rules",
        policy_version="2026.06.27",
        now=SURICATA_NOW,
        max_age_days=30,
    )

    assert result.approved is False
    assert result.reason == "SURICATA_POLICY_STALE_TIMESTAMP"


def test_malformed_registry_fails() -> None:
    result = SuricataPolicyRegistry.from_dicts([registry_record(rule_count=0, evidence_hash="sha256:bad")]).validate(
        policy_id="suricata-managed-rules",
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )

    assert result.approved is False
    assert result.reason == "SURICATA_POLICY_REGISTRY_MALFORMED"


def test_missing_approval_fails() -> None:
    result = SuricataPolicyRegistry.from_dicts([registry_record(approved_by="")]).validate(
        policy_id="suricata-managed-rules",
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )

    assert result.approved is False
    assert result.reason == "SURICATA_POLICY_APPROVAL_MISSING"


def test_unknown_policy_fails() -> None:
    result = SuricataPolicyRegistry.from_dicts([registry_record()]).validate(
        policy_id="unknown",
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )

    assert result.approved is False
    assert result.reason == "SURICATA_POLICY_UNKNOWN"


def test_policy_hash_mismatch_fails() -> None:
    result = SuricataPolicyRegistry.from_dicts([registry_record(evidence_hash=hash_payload("different"))]).validate(
        policy_id="suricata-managed-rules",
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )

    assert result.approved is False
    assert result.reason == "SURICATA_POLICY_HASH_MISMATCH"


def test_deterministic_evidence_hash_and_registry_hash() -> None:
    first = valid_registry_result()
    second = valid_registry_result()

    assert first.evidence_hash == second.evidence_hash
    assert first.registry_hash == second.registry_hash


def test_runtime_aggregator_blocks_missing_registry() -> None:
    result = aggregate_with_registry(None)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_POLICY_REGISTRY_MISSING"


def test_runtime_aggregator_blocks_rejected_registry() -> None:
    rejected = SuricataPolicyRegistry.from_dicts([registry_record(revoked=True)]).validate(
        policy_id="suricata-managed-rules",
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )

    result = aggregate_with_registry(rejected)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_POLICY_REVOKED"


def test_regression_suricata_001_and_002_with_registry_pass() -> None:
    result = aggregate_with_registry(valid_registry_result())

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["suricata_policy_registry_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["suricata_decision"] == "ALLOW"
