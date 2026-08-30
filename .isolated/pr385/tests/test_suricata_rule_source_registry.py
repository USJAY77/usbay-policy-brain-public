from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.models import ApprovalEvidence, BlockReason, RegistryRecord, hash_payload
from publication.policy_bundle_readiness import evaluate_policy_bundle_readiness
from publication.policy_bundle_validator import load_publication_policy_bundle, validate_policy_bundle
from publication.registry_store import load_json_file
from publication.runtime_aggregator import aggregate_runtime_publication_decision, aggregate_runtime_publication_report
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


def source_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "approved_source_id": "suricata-source-managed",
        "source_name": "Managed Suricata Rules",
        "source_uri_hash": hash_payload("https://rules.invalid/suricata"),
        "approved_public_key_hash": hash_payload("suricata-public-key"),
        "approved_policy_version": "2026.06.27",
        "max_age_seconds": 86400,
        "revoked": False,
        "human_approval_id": "approval-suricata-source-001",
    }
    record.update(overrides)
    return record


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


def source_registry_result(records: list[dict[str, object]] | None = None):
    return SuricataRuleSourceRegistry(records or [source_record()]).validate_source(
        approved_source_id="suricata-source-managed",
        policy_version="2026.06.27",
    )


def source_dataclass(**overrides: object) -> SuricataRuleSourceRecord:
    return SuricataRuleSourceRecord.from_dict(source_record(**overrides))


def signature_metadata(**overrides: object) -> dict[str, object]:
    public_key_hash = str(overrides.pop("public_key_hash", hash_payload("suricata-public-key")))
    policy_version = str(overrides.pop("policy_version", "2026.06.27"))
    rule_bundle_hash = str(overrides.pop("rule_bundle_hash", hash_payload("local-rule-bundle")))
    metadata: dict[str, object] = {
        "approved_source_id": "suricata-source-managed",
        "policy_version": policy_version,
        "rule_bundle_hash": rule_bundle_hash,
        "public_key_hash": public_key_hash,
        "signature_hash": expected_rule_signature_hash(
            rule_bundle_hash=rule_bundle_hash,
            public_key_hash=public_key_hash,
            policy_version=policy_version,
        ),
        "generated_at": "2026-06-26T12:00:00Z",
        "rule_count": 42,
    }
    metadata.update(overrides)
    return metadata


def valid_signature_result():
    registry_result = source_registry_result()
    return verify_suricata_rule_signature(
        metadata=signature_metadata(),
        source_record=source_dataclass(),
        source_registry_result=registry_result,
        now=SURICATA_NOW,
    )


def policy_registry_result():
    signature_hash = hash_payload("signed-suricata-ruleset-v1")
    return SuricataPolicyRegistry.from_dicts(
        [
            {
                "policy_id": "suricata-managed-rules",
                "policy_version": "2026.06.27",
                "signature_hash": signature_hash,
                "evidence_hash": suricata_policy_evidence_hash(
                    policy_id="suricata-managed-rules",
                    policy_version="2026.06.27",
                    signature_hash=signature_hash,
                    rule_count=42,
                ),
                "rule_count": 42,
                "created_at": "2026-06-26T00:00:00Z",
                "approved_by": "governance-reviewer",
                "approval_timestamp": "2026-06-26T01:00:00Z",
                "active": True,
                "revoked": False,
            }
        ]
    ).validate(policy_id="suricata-managed-rules", policy_version="2026.06.27", now=SURICATA_NOW)


def suricata_evidence_and_gate():
    evidence = evaluate_suricata_eve_json(
        {
            "event_type": "alert",
            "alert": {"severity": 1, "signature": "Low", "category": "Policy"},
            "src_ip": "192.0.2.10",
            "dest_ip": "198.51.100.20",
            "payload": "raw-rule-payload",
        },
        threshold=0,
    )
    gate = evaluate_suricata_policy_gate(
        evidence,
        {"policy_version": "USBAY-SURICATA-002", "severity_threshold": 2, "action_on_threshold_exceeded": "BLOCK"},
    )
    return evidence, gate


def aggregate(rule_source_result):
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, gate = suricata_evidence_and_gate()
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
        suricata_policy_registry=policy_registry_result(),
        suricata_rule_source=rule_source_result,
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
    )


def test_approved_source_passes() -> None:
    result = source_registry_result()
    signature = valid_signature_result()

    assert result.approved is True
    assert result.reason == "SURICATA_RULE_SOURCE_APPROVED"
    assert signature.approved is True
    assert signature.reason == "SURICATA_RULE_SIGNATURE_APPROVED"


def test_unknown_source_fails() -> None:
    result = SuricataRuleSourceRegistry([source_record()]).validate_source(
        approved_source_id="unknown-source",
        policy_version="2026.06.27",
    )

    assert result.approved is False
    assert result.reason == "SURICATA_RULE_SOURCE_UNKNOWN"


def test_revoked_source_fails() -> None:
    result = source_registry_result([source_record(revoked=True)])

    assert result.approved is False
    assert result.reason == "SURICATA_RULE_SOURCE_REVOKED"


def test_stale_source_fails() -> None:
    registry_result = source_registry_result()
    signature = verify_suricata_rule_signature(
        metadata=signature_metadata(generated_at="2026-06-20T00:00:00Z"),
        source_record=source_dataclass(max_age_seconds=60),
        source_registry_result=registry_result,
        now=SURICATA_NOW,
    )

    assert signature.approved is False
    assert signature.reason == "SURICATA_RULE_SOURCE_STALE"


def test_policy_mismatch_fails() -> None:
    result = source_registry_result([source_record(approved_policy_version="2026.06.01")])

    assert result.approved is False
    assert result.reason == "SURICATA_RULE_SOURCE_POLICY_MISMATCH"


def test_signature_key_hash_mismatch_fails() -> None:
    registry_result = source_registry_result()
    signature = verify_suricata_rule_signature(
        metadata=signature_metadata(public_key_hash=hash_payload("other-key")),
        source_record=source_dataclass(),
        source_registry_result=registry_result,
        now=SURICATA_NOW,
    )

    assert signature.approved is False
    assert signature.reason == "SURICATA_RULE_SIGNATURE_KEY_MISMATCH"


def test_signature_hash_mismatch_fails() -> None:
    registry_result = source_registry_result()
    signature = verify_suricata_rule_signature(
        metadata=signature_metadata(signature_hash=hash_payload("wrong-signature")),
        source_record=source_dataclass(),
        source_registry_result=registry_result,
        now=SURICATA_NOW,
    )

    assert signature.approved is False
    assert signature.reason == "SURICATA_RULE_SIGNATURE_MISMATCH"


def test_missing_human_approval_fails() -> None:
    result = source_registry_result([source_record(human_approval_id="")])

    assert result.approved is False
    assert result.reason == "SURICATA_RULE_SOURCE_APPROVAL_MISSING"


def test_malformed_registry_fails() -> None:
    result = source_registry_result([source_record(source_uri_hash="raw-uri")])

    assert result.approved is False
    assert result.reason == "SURICATA_RULE_SOURCE_REGISTRY_MALFORMED"


def test_deterministic_registry_hash() -> None:
    first = source_registry_result()
    second = source_registry_result()

    assert first.registry_hash == second.registry_hash


def test_deterministic_signature_evidence_hash() -> None:
    first = valid_signature_result()
    second = valid_signature_result()

    assert first.evidence_hash == second.evidence_hash


def test_runtime_aggregator_blocks_missing_rule_source() -> None:
    result = aggregate(None)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_RULE_SOURCE_MISSING"


def test_runtime_aggregator_blocks_invalid_rule_source() -> None:
    result = aggregate(verify_suricata_rule_signature(metadata=None, source_record=None, source_registry_result=None))

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_RULE_SIGNATURE_METADATA_MISSING"


def test_runtime_aggregator_allows_with_valid_rule_source() -> None:
    result = aggregate(valid_signature_result())

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["suricata_rule_source_hash"].startswith("sha256:")


def test_no_raw_rule_payload_in_final_report() -> None:
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, gate = suricata_evidence_and_gate()

    report = aggregate_runtime_publication_report(
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
        suricata_policy_registry=policy_registry_result(),
        suricata_rule_source=valid_signature_result(),
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
    )

    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert report.report_complete is True
    assert "raw-rule-payload" not in rendered
    assert "rules.invalid" not in rendered


def test_suricata_001_002_003_regression_still_passes() -> None:
    result = aggregate(valid_signature_result())

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["suricata_decision"] == "ALLOW"
    assert result.audit.evidence_hashes["suricata_policy_registry_hash"].startswith("sha256:")
