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
from publication.suricata_external_signing_authority import (
    suricata_signing_authority_hash,
    validate_suricata_external_signing_authority,
)
from publication.suricata_policy_gate import evaluate_suricata_policy_gate
from publication.suricata_policy_manifest import suricata_policy_evidence_hash
from publication.suricata_policy_registry import SuricataPolicyRegistry
from publication.suricata_rule_signature import expected_rule_signature_hash, verify_suricata_rule_signature
from publication.suricata_rule_source_registry import SuricataRuleSourceRecord, SuricataRuleSourceRegistry
from publication.suricata_trust_anchor_store import SuricataTrustAnchorStore, finalize_suricata_trust_anchor, suricata_trust_anchor_record_hash


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


def authority_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "authority_id": "suricata-signing-authority-managed",
        "authority_fingerprint": hash_payload("suricata-public-key"),
        "policy_version": "2026.06.27",
        "approved": True,
        "human_approved": True,
        "issued_at": "2026-06-26T00:00:00Z",
        "expires_at": "2026-07-27T00:00:00Z",
    }
    payload.update(overrides)
    payload["evidence_hash"] = suricata_signing_authority_hash(
        authority_id=str(payload["authority_id"]),
        authority_fingerprint=str(payload["authority_fingerprint"]),
        policy_version=str(payload["policy_version"]),
        approved=payload["approved"] is True,
        human_approved=payload["human_approved"] is True,
        issued_at=str(payload["issued_at"]),
        expires_at=str(payload["expires_at"]),
    )
    return payload


def signing_authority_result(**overrides: object):
    payload = authority_payload(**overrides)
    return validate_suricata_external_signing_authority(
        payload,
        expected_fingerprint=hash_payload("suricata-public-key"),
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )


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


def rule_source_result():
    source = {
        "approved_source_id": "suricata-source-managed",
        "source_name": "Managed Suricata Rules",
        "source_uri_hash": hash_payload("https://rules.invalid/suricata"),
        "approved_public_key_hash": hash_payload("suricata-public-key"),
        "approved_policy_version": "2026.06.27",
        "max_age_seconds": 86400,
        "revoked": False,
        "human_approval_id": "approval-suricata-source-001",
    }
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


def suricata_evidence_and_gate():
    evidence = evaluate_suricata_eve_json(
        {
            "event_type": "alert",
            "alert": {"severity": 1, "signature": "Low", "category": "Policy"},
            "src_ip": "192.0.2.10",
            "dest_ip": "198.51.100.20",
            "payload": "payload-bytes",
            "http": {"hostname": "example.com", "http_user_agent": "Mozilla/5.0"},
            "username": "alice",
        },
        threshold=0,
    )
    gate = evaluate_suricata_policy_gate(
        evidence,
        {"policy_version": "USBAY-SURICATA-002", "severity_threshold": 2, "action_on_threshold_exceeded": "BLOCK"},
    )
    return evidence, gate


def aggregate(authority=None):
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
        suricata_rule_source=rule_source_result(),
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=authority,
    )


def test_valid_approved_authority_passes() -> None:
    result = signing_authority_result()

    assert result.approved is True
    assert result.reason == "SURICATA_SIGNING_AUTHORITY_APPROVED"
    assert result.evidence_hash.startswith("sha256:")


def test_missing_authority_blocks_runtime() -> None:
    result = aggregate(authority=None)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_SIGNING_AUTHORITY_MISSING"


def test_revoked_authority_blocks() -> None:
    result = signing_authority_result(approved=False)

    assert result.approved is False
    assert result.reason == "SURICATA_SIGNING_AUTHORITY_REVOKED"


def test_expired_authority_blocks() -> None:
    result = signing_authority_result(expires_at="2026-06-26T23:59:00Z")

    assert result.approved is False
    assert result.reason == "SURICATA_SIGNING_AUTHORITY_EXPIRED"


def test_malformed_authority_blocks() -> None:
    result = validate_suricata_external_signing_authority(
        {"authority_id": "bad"},
        expected_fingerprint=hash_payload("suricata-public-key"),
        policy_version="2026.06.27",
        now=SURICATA_NOW,
    )

    assert result.approved is False
    assert result.reason == "SURICATA_SIGNING_AUTHORITY_MALFORMED"


def test_fingerprint_mismatch_blocks() -> None:
    result = signing_authority_result(authority_fingerprint=hash_payload("other-key"))

    assert result.approved is False
    assert result.reason == "SURICATA_SIGNING_AUTHORITY_FINGERPRINT_MISMATCH"


def test_policy_version_mismatch_blocks() -> None:
    result = signing_authority_result(policy_version="2026.06.01")

    assert result.approved is False
    assert result.reason == "SURICATA_SIGNING_AUTHORITY_POLICY_MISMATCH"


def test_missing_human_approval_blocks() -> None:
    result = signing_authority_result(human_approved=False)

    assert result.approved is False
    assert result.reason == "SURICATA_SIGNING_AUTHORITY_HUMAN_APPROVAL_MISSING"


def test_evidence_hash_is_deterministic() -> None:
    assert signing_authority_result().evidence_hash == signing_authority_result().evidence_hash


def test_final_report_excludes_public_key_cert_and_raw_source_material() -> None:
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
    assert report.suricata_signing_authority_hash == signing_authority_result().evidence_hash
    for raw_value in (
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN PUBLIC KEY-----",
        "suricata-public-key",
        "https://rules.invalid/suricata",
        "192.0.2.10",
        "198.51.100.20",
        "example.com",
        "payload-bytes",
        "Mozilla/5.0",
        "alice",
    ):
        assert raw_value not in rendered
