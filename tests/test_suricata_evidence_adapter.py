from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.models import ApprovalEvidence, BlockReason, PublicationDecision, RegistryRecord, hash_payload
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


def policy(threshold: int = 2) -> dict[str, object]:
    return {
        "policy_version": "USBAY-SURICATA-002",
        "severity_threshold": threshold,
        "action_on_threshold_exceeded": "BLOCK",
    }


def registry_result():
    signature_hash = "sha256:suricata-signature"
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
    ).validate(policy_id="suricata-managed-rules", policy_version="2026.06.27", now=datetime.fromisoformat("2026-06-27T00:00:00+00:00"))


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


def aggregate(record: RegistryRecord, suricata_evidence, gate=None):
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
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
        suricata_evidence=suricata_evidence,
        suricata_policy_gate=gate if gate is not None else evaluate_suricata_policy_gate(suricata_evidence, policy()),
        suricata_policy_registry=registry_result(),
        suricata_rule_source=rule_source_result(),
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
    )


def eve_alert(**overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "event_type": "alert",
        "timestamp": "2026-06-27T10:00:00.000000+0000",
        "flow_id": 12345,
        "src_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "src_port": 44321,
        "dest_port": 443,
        "proto": "TCP",
        "hostname": "corp.internal",
        "dns": {"rrname": "evil.test"},
        "http": {"hostname": "example.com", "url": "/private", "http_user_agent": "Mozilla/5.0"},
        "payload": "payload-bytes",
        "username": "alice",
        "alert": {
            "signature": "ET POLICY Suspicious outbound connection",
            "category": "Attempted Information Leak",
            "severity": 4,
        },
    }
    event.update(overrides)
    return event


def test_valid_low_risk_alert_passes() -> None:
    result = evaluate_suricata_eve_json(eve_alert(), threshold=2)

    assert result.accepted is True
    assert result.blocked is False
    assert result.severity == 4
    assert result.evidence_hash.startswith("sha256:")
    assert result.reason == "SURICATA_EVIDENCE_ACCEPTED"


def test_high_risk_severity_blocks() -> None:
    result = evaluate_suricata_eve_json(eve_alert(alert={"severity": 1, "signature": "C2", "category": "Malware"}), threshold=2)

    assert result.accepted is True
    assert result.blocked is True
    assert result.reason == "SURICATA_SEVERITY_THRESHOLD_BLOCKED"


def test_malformed_json_fails_closed() -> None:
    result = evaluate_suricata_eve_json("{not-json", threshold=2)

    assert result.accepted is False
    assert result.blocked is True
    assert result.reason == "SURICATA_EVE_JSON_MALFORMED"


def test_missing_severity_fails_closed() -> None:
    result = evaluate_suricata_eve_json(eve_alert(alert={"signature": "missing severity"}), threshold=2)

    assert result.accepted is False
    assert result.reason == "SURICATA_ALERT_SEVERITY_INVALID"


def test_non_alert_fails_closed() -> None:
    result = evaluate_suricata_eve_json({"event_type": "dns", "dns": {"rrname": "evil.test"}}, threshold=2)

    assert result.accepted is False
    assert result.reason == "SURICATA_NON_ALERT_EVENT"


def test_threshold_missing_fails_closed() -> None:
    result = evaluate_suricata_eve_json(eve_alert(), threshold=None)

    assert result.accepted is False
    assert result.reason == "SURICATA_THRESHOLD_MISSING"


def test_redaction_removes_ips_domains_payload_and_user_agent() -> None:
    result = evaluate_suricata_eve_json(eve_alert(), threshold=2)
    rendered = json.dumps(result.redacted_event, sort_keys=True)

    for raw_value in (
        "192.0.2.10",
        "198.51.100.20",
        "corp.internal",
        "evil.test",
        "example.com",
        "payload-bytes",
        "Mozilla/5.0",
        "alice",
    ):
        assert raw_value not in rendered
    assert "REDACTED_HASH_ONLY" in rendered


def test_evidence_hash_is_deterministic() -> None:
    first = evaluate_suricata_eve_json(eve_alert(), threshold=2)
    second = evaluate_suricata_eve_json(eve_alert(), threshold=2)

    assert first.evidence_hash == second.evidence_hash


def test_evidence_hash_changes_when_redacted_event_changes() -> None:
    first = evaluate_suricata_eve_json(eve_alert(flow_id=12345), threshold=2)
    second = evaluate_suricata_eve_json(eve_alert(flow_id=67890), threshold=2)

    assert first.evidence_hash != second.evidence_hash


def test_aggregator_blocks_when_suricata_blocks() -> None:
    record = example_record()
    suricata = evaluate_suricata_eve_json(eve_alert(alert={"severity": 3, "signature": "C2", "category": "Malware"}), threshold=0)
    gate = evaluate_suricata_policy_gate(suricata, policy(2))

    result = aggregate(record, suricata, gate)

    assert result.publish_allowed is False
    assert result.decision == PublicationDecision.BLOCK_PUBLICATION
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_BLOCKED
    assert result.audit.evidence_hashes["suricata_evidence_hash"] == gate.evidence_hash


def test_aggregator_allows_only_when_suricata_result_is_accepted_and_not_blocked() -> None:
    record = example_record()
    suricata = evaluate_suricata_eve_json(eve_alert(alert={"severity": 1, "signature": "Low", "category": "Policy"}), threshold=0)
    gate = evaluate_suricata_policy_gate(suricata, policy(2))

    result = aggregate(record, suricata, gate)

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["suricata_evidence_hash"] == gate.evidence_hash
    assert result.audit.evidence_hashes["suricata_policy_version"] == gate.policy_version
    assert result.audit.evidence_hashes["suricata_reason"] == gate.reason


def test_no_raw_sensitive_fields_in_report_output() -> None:
    record = example_record()
    suricata = evaluate_suricata_eve_json(eve_alert(alert={"severity": 1, "signature": "Low", "category": "Policy"}), threshold=0)
    gate = evaluate_suricata_policy_gate(suricata, policy(2))
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())

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
        suricata_evidence=suricata,
        suricata_policy_gate=gate,
        suricata_policy_registry=registry_result(),
        suricata_rule_source=rule_source_result(),
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
    )
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert report.report_complete is True
    assert report.suricata_evidence_hash == gate.evidence_hash
    assert report.suricata_policy_version == gate.policy_version
    assert report.suricata_reason == gate.reason
    for raw_value in ("192.0.2.10", "198.51.100.20", "evil.test", "payload-bytes", "Mozilla/5.0", "alice"):
        assert raw_value not in rendered
