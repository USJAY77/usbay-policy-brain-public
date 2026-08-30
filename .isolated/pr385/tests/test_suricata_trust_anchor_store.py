from __future__ import annotations

import json
from dataclasses import replace
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


def anchor_record(**overrides: object) -> dict[str, object]:
    fingerprint = str(overrides.pop("public_key_fingerprint", hash_payload("suricata-public-key")))
    record: dict[str, object] = {
        "anchor_id": "suricata-anchor-managed",
        "issuer": "USBAY Suricata Governance",
        "public_key_fingerprint": fingerprint,
        "status": "approved",
        "approved_by_human": True,
        "policy_version": "2026.06.27",
        "created_at": "2026-06-26T00:00:00Z",
    }
    record.update(overrides)
    record["evidence_hash"] = suricata_trust_anchor_record_hash(
        anchor_id=str(record["anchor_id"]),
        issuer=str(record["issuer"]),
        public_key_fingerprint=str(record["public_key_fingerprint"]),
        status=str(record["status"]),
        approved_by_human=record["approved_by_human"] is True,
        policy_version=str(record["policy_version"]),
        created_at=str(record["created_at"]),
    )
    return record


def trust_anchor_result(record: dict[str, object] | None = None, *, expected_fingerprint: str | None = None, policy_version: str = "2026.06.27"):
    fingerprint = expected_fingerprint or hash_payload("suricata-public-key")
    return SuricataTrustAnchorStore([record or anchor_record()]).validate_anchor(
        anchor_id="suricata-anchor-managed",
        expected_fingerprint=fingerprint,
        policy_version=policy_version,
    )


def trust_anchor_finalizer_result(anchor=None):
    return finalize_suricata_trust_anchor(anchor if anchor is not None else trust_anchor_result())


def source_record() -> dict[str, object]:
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


def rule_source_result():
    source = source_record()
    registry = SuricataRuleSourceRegistry([source]).validate_source(
        approved_source_id="suricata-source-managed",
        policy_version="2026.06.27",
    )
    public_key_hash = hash_payload("suricata-public-key")
    rule_bundle_hash = hash_payload("local-rule-bundle")
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
            "payload": "payload-bytes",
        },
        threshold=0,
    )
    gate = evaluate_suricata_policy_gate(
        evidence,
        {"policy_version": "USBAY-SURICATA-002", "severity_threshold": 2, "action_on_threshold_exceeded": "BLOCK"},
    )
    return evidence, gate


def aggregate(anchor, finalizer="default"):
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, gate = suricata_evidence_and_gate()
    resolved_finalizer = trust_anchor_finalizer_result(anchor) if finalizer == "default" and anchor is not None else finalizer
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
        suricata_rule_source=rule_source_result(),
        suricata_trust_anchor=anchor,
        suricata_trust_anchor_finalizer=resolved_finalizer,
        suricata_signing_authority=signing_authority_result(),
    )


def test_valid_trust_anchor_passes() -> None:
    result = trust_anchor_result()
    finalizer = trust_anchor_finalizer_result(result)

    assert result.approved is True
    assert result.reason == "SURICATA_TRUST_ANCHOR_APPROVED"
    assert result.evidence_hash.startswith("sha256:")
    assert finalizer.approved is True
    assert finalizer.trust_anchor_id == result.anchor_id
    assert finalizer.policy_version == result.policy_version
    assert finalizer.fingerprint_hash.startswith("sha256:")
    assert finalizer.approval_hash.startswith("sha256:")
    assert finalizer.trust_anchor_evidence_hash == result.evidence_hash
    assert finalizer.finalizer_decision == "ALLOW"
    assert finalizer.finalizer_reason == "SURICATA_TRUST_ANCHOR_FINALIZER_APPROVED"


def test_missing_anchor_fails() -> None:
    result = SuricataTrustAnchorStore([]).validate_anchor(
        anchor_id="suricata-anchor-managed",
        expected_fingerprint=hash_payload("suricata-public-key"),
        policy_version="2026.06.27",
    )

    assert result.approved is False
    assert result.reason == "SURICATA_TRUST_ANCHOR_MISSING"


def test_revoked_anchor_fails() -> None:
    result = trust_anchor_result(anchor_record(status="revoked"))

    assert result.approved is False
    assert result.reason == "SURICATA_TRUST_ANCHOR_REVOKED"


def test_missing_human_approval_fails() -> None:
    result = trust_anchor_result(anchor_record(approved_by_human=False))

    assert result.approved is False
    assert result.reason == "SURICATA_TRUST_ANCHOR_HUMAN_APPROVAL_MISSING"


def test_fingerprint_mismatch_fails() -> None:
    result = trust_anchor_result(expected_fingerprint=hash_payload("other-key"))

    assert result.approved is False
    assert result.reason == "SURICATA_TRUST_ANCHOR_FINGERPRINT_MISMATCH"


def test_policy_version_mismatch_fails() -> None:
    result = trust_anchor_result(policy_version="2026.06.01")

    assert result.approved is False
    assert result.reason == "SURICATA_TRUST_ANCHOR_POLICY_MISMATCH"


def test_malformed_anchor_fails() -> None:
    result = trust_anchor_result(anchor_record(public_key_fingerprint="raw-public-key"))

    assert result.approved is False
    assert result.reason == "SURICATA_TRUST_ANCHOR_MALFORMED"


def test_missing_evidence_hash_fails() -> None:
    record = anchor_record()
    record["evidence_hash"] = ""

    result = trust_anchor_result(record)

    assert result.approved is False
    assert result.reason == "SURICATA_TRUST_ANCHOR_EVIDENCE_MISSING"


def test_missing_trust_anchor_evidence_hash_finalizer_fails() -> None:
    anchor = replace(trust_anchor_result(), evidence_hash="")
    finalizer = trust_anchor_finalizer_result(anchor)

    assert finalizer.approved is False
    assert finalizer.finalizer_reason == "SURICATA_TRUST_ANCHOR_FINALIZER_EVIDENCE_MISSING"


def test_deterministic_trust_anchor_evidence_hash() -> None:
    first = trust_anchor_finalizer_result()
    second = trust_anchor_finalizer_result()

    assert first.evidence_hash == second.evidence_hash


def test_runtime_aggregator_blocks_missing_trust_anchor() -> None:
    result = aggregate(None, finalizer=None)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_TRUST_ANCHOR_MISSING"


def test_runtime_aggregator_blocks_rejected_trust_anchor() -> None:
    rejected = trust_anchor_result(anchor_record(status="revoked"))
    result = aggregate(rejected, trust_anchor_finalizer_result(rejected))

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_TRUST_ANCHOR_REVOKED"


def test_runtime_aggregator_blocks_without_trust_anchor_finalizer() -> None:
    result = aggregate(trust_anchor_result(), finalizer=None)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_TRUST_ANCHOR_FINALIZER_MISSING"


def test_runtime_aggregator_allows_with_trust_anchor() -> None:
    result = aggregate(trust_anchor_result())

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["suricata_trust_anchor_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["suricata_trust_anchor_finalizer_hash"].startswith("sha256:")


def test_final_report_excludes_public_key_material_and_raw_rules() -> None:
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
        suricata_rule_source=rule_source_result(),
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
    )
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert report.report_complete is True
    assert "suricata-public-key" not in rendered
    assert "raw-public-key" not in rendered
    assert "alert http" not in rendered
