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
from publication.suricata_fetch_receipt import suricata_fetch_receipt_hash, validate_suricata_fetch_receipt
from publication.suricata_fetch_receipt_finalizer import finalize_suricata_fetch_receipt
from publication.suricata_policy_gate import evaluate_suricata_policy_gate
from publication.suricata_policy_manifest import suricata_policy_evidence_hash
from publication.suricata_policy_registry import SuricataPolicyRegistry
from publication.suricata_rule_signature import expected_rule_signature_hash, verify_suricata_rule_signature
from publication.suricata_rule_source_fetcher import LocalRuleSourceFetchRequest, evaluate_local_rule_source_fetch
from publication.suricata_rule_source_registry import SuricataRuleSourceRecord, SuricataRuleSourceRegistry
from publication.suricata_trust_anchor_store import SuricataTrustAnchorStore, finalize_suricata_trust_anchor, suricata_trust_anchor_record_hash
from test_suricata_external_signing_authority import signing_authority_result
from test_suricata_live_fetcher_gate import gate as live_fetcher_gate, live_network_fetch_result, publication_connector_result


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "policy" / "publication" / "publication_registry_record.example.json"
SCHEMA_PATH = ROOT / "policy" / "publication" / "publication_registry_schema.json"
CLASSIFICATION_POLICY_PATH = ROOT / "policy" / "publication" / "publication_classification_policy.json"
APPROVAL_POLICY_PATH = ROOT / "policy" / "publication" / "publication_approval_policy.json"
NOW = datetime.fromisoformat("2026-06-25T00:00:00+00:00")
SURICATA_NOW = datetime.fromisoformat("2026-06-27T00:00:00+00:00")
RULE_CONTENT = "alert http any any -> any any (msg:\"USBAY finalizer test\"; sid:1000003; rev:1;)"


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


def rule_file(tmp_path: Path) -> Path:
    path = tmp_path / "suricata.rules"
    path.write_text(RULE_CONTENT, encoding="utf-8")
    return path


def rule_bundle_hash(path: Path) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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


def source_registry_result():
    return SuricataRuleSourceRegistry([source_record()]).validate_source(
        approved_source_id="suricata-source-managed",
        policy_version="2026.06.27",
    )


def rule_signature_result(path: Path):
    source = source_record()
    registry = source_registry_result()
    public_key_hash = hash_payload("suricata-public-key")
    bundle_hash = rule_bundle_hash(path)
    return verify_suricata_rule_signature(
        metadata={
            "approved_source_id": "suricata-source-managed",
            "policy_version": "2026.06.27",
            "rule_bundle_hash": bundle_hash,
            "public_key_hash": public_key_hash,
            "signature_hash": expected_rule_signature_hash(
                rule_bundle_hash=bundle_hash,
                public_key_hash=public_key_hash,
                policy_version="2026.06.27",
            ),
            "generated_at": "2026-06-26T12:00:00Z",
            "rule_count": 1,
        },
        source_record=SuricataRuleSourceRecord.from_dict(source),
        source_registry_result=registry,
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


def fetch_receipt_result(path: Path, **overrides: object):
    payload: dict[str, object] = {
        "source_id": "suricata-source-managed",
        "source_registry_hash": source_registry_result().evidence_hash,
        "rule_bundle_hash": rule_bundle_hash(path),
        "trust_anchor_hash": trust_anchor_finalizer_result().evidence_hash,
        "fetched_at": "2026-06-26T12:00:00Z",
        "freshness_window_seconds": 172800,
        "human_approval_id": "approval-suricata-fetch-001",
    }
    payload.update(overrides)
    payload["fetch_receipt_hash"] = suricata_fetch_receipt_hash(
        source_id=str(payload["source_id"]),
        source_registry_hash=str(payload["source_registry_hash"]),
        rule_bundle_hash=str(payload["rule_bundle_hash"]),
        trust_anchor_hash=str(payload["trust_anchor_hash"]),
        fetched_at=str(payload["fetched_at"]),
        freshness_window_seconds=int(payload["freshness_window_seconds"]),
        human_approval_id=str(payload["human_approval_id"]),
    )
    return validate_suricata_fetch_receipt(payload, now=SURICATA_NOW)


def local_fetch_result(path: Path):
    signature = rule_signature_result(path)
    registry = source_registry_result()
    request = LocalRuleSourceFetchRequest(
        source_id="suricata-source-managed",
        local_path=str(path),
        registry_evidence_hash=registry.evidence_hash,
        signature_evidence_hash=signature.evidence_hash,
        policy_version="2026.06.27",
        requested_at="2026-06-27T00:00:00Z",
    )
    return evaluate_local_rule_source_fetch(request, source_registry_result=registry, signature_result=signature)


def finalizer_result(tmp_path: Path, **overrides):
    path = rule_file(tmp_path)
    values = {
        "source_registry": source_registry_result(),
        "source_signature": rule_signature_result(path),
        "trust_anchor": trust_anchor_result(),
        "trust_anchor_finalizer": trust_anchor_finalizer_result(),
        "fetch_receipt": fetch_receipt_result(path),
        "local_fetch": local_fetch_result(path),
    }
    values.update(overrides)
    return finalize_suricata_fetch_receipt(**values)


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


def aggregate(tmp_path: Path, finalizer=None):
    path = rule_file(tmp_path)
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
        suricata_rule_source=rule_signature_result(path),
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
        suricata_live_rule_source_enabled=True,
        suricata_rule_source_fetcher=local_fetch_result(path),
        suricata_fetch_receipt=fetch_receipt_result(path),
        suricata_fetch_finalizer=finalizer,
        suricata_live_fetcher_gate=live_fetcher_gate(tmp_path),
        suricata_live_network_fetch=live_network_fetch_result(tmp_path),
        suricata_publication_connector=publication_connector_result(tmp_path),
    )


def test_finalizer_passes_with_complete_chain(tmp_path: Path) -> None:
    result = finalizer_result(tmp_path)

    assert result.approved is True
    assert result.decision == "ALLOW"
    assert result.reason == "SURICATA_FETCH_FINALIZER_APPROVED"
    assert result.final_suricata_fetch_hash.startswith("sha256:")


def test_missing_prior_object_fails(tmp_path: Path) -> None:
    result = finalizer_result(tmp_path, source_registry=None)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_FINALIZER_REGISTRY_MISSING"


def test_rejected_fetch_receipt_fails(tmp_path: Path) -> None:
    path = rule_file(tmp_path)
    rejected = fetch_receipt_result(path, fetched_at="2026-06-20T00:00:00Z", freshness_window_seconds=60)
    result = finalizer_result(tmp_path, fetch_receipt=rejected)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_STALE"


def test_rule_bundle_hash_mismatch_fails(tmp_path: Path) -> None:
    path = rule_file(tmp_path)
    mismatched_receipt = fetch_receipt_result(path, rule_bundle_hash=hash_payload("other-bundle"))
    result = finalizer_result(tmp_path, fetch_receipt=mismatched_receipt)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_FINALIZER_BUNDLE_HASH_MISMATCH"


def test_policy_version_mismatch_fails(tmp_path: Path) -> None:
    signature = replace(rule_signature_result(rule_file(tmp_path)), policy_version="2026.06.01")
    result = finalizer_result(tmp_path, source_signature=signature)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_FINALIZER_POLICY_MISMATCH"


def test_missing_human_approval_fails(tmp_path: Path) -> None:
    path = rule_file(tmp_path)
    receipt = fetch_receipt_result(path, human_approval_id="")
    result = finalizer_result(tmp_path, fetch_receipt=receipt)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_HUMAN_APPROVAL_MISSING"


def test_malformed_object_fails(tmp_path: Path) -> None:
    signature = replace(rule_signature_result(rule_file(tmp_path)), evidence_hash="bad")
    result = finalizer_result(tmp_path, source_signature=signature)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_FINALIZER_MALFORMED"


def test_deterministic_final_suricata_fetch_hash(tmp_path: Path) -> None:
    first = finalizer_result(tmp_path)
    second = finalizer_result(tmp_path)

    assert first.final_suricata_fetch_hash == second.final_suricata_fetch_hash


def test_runtime_aggregator_blocks_missing_finalizer(tmp_path: Path) -> None:
    result = aggregate(tmp_path, finalizer=None)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_FETCH_FINALIZER_MISSING"


def test_runtime_aggregator_allows_with_finalizer(tmp_path: Path) -> None:
    finalizer = finalizer_result(tmp_path)
    result = aggregate(tmp_path, finalizer=finalizer)

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["final_suricata_fetch_hash"] == finalizer.final_suricata_fetch_hash


def test_final_report_never_leaks_raw_suricata_content(tmp_path: Path) -> None:
    path = rule_file(tmp_path)
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, gate = suricata_evidence_and_gate()
    finalizer = finalizer_result(tmp_path)

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
        suricata_rule_source=rule_signature_result(path),
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
        suricata_live_rule_source_enabled=True,
        suricata_rule_source_fetcher=local_fetch_result(path),
        suricata_fetch_receipt=fetch_receipt_result(path),
        suricata_fetch_finalizer=finalizer,
        suricata_live_fetcher_gate=live_fetcher_gate(tmp_path),
        suricata_live_network_fetch=live_network_fetch_result(tmp_path),
        suricata_publication_connector=publication_connector_result(tmp_path),
    )
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert report.report_complete is True
    for raw_value in (
        RULE_CONTENT,
        "USBAY finalizer test",
        "192.0.2.10",
        "198.51.100.20",
        "example.com",
        "payload-bytes",
        "Mozilla/5.0",
        "alice",
        "https://rules.invalid/suricata",
    ):
        assert raw_value not in rendered
