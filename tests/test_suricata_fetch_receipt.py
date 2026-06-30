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
RULE_CONTENT = "alert http any any -> any any (msg:\"USBAY receipt test\"; sid:1000002; rev:1;)"


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


def rule_bundle_hash(path: Path) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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


def receipt_payload(path: Path, **overrides: object) -> dict[str, object]:
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
    return payload


def valid_receipt_result(tmp_path: Path):
    return validate_suricata_fetch_receipt(receipt_payload(rule_file(tmp_path)), now=SURICATA_NOW)


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


def fetcher_result(path: Path):
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


def finalizer_result(path: Path):
    return finalize_suricata_fetch_receipt(
        source_registry=source_registry_result(),
        source_signature=rule_signature_result(path),
        trust_anchor=trust_anchor_result(),
        trust_anchor_finalizer=trust_anchor_finalizer_result(),
        fetch_receipt=validate_suricata_fetch_receipt(receipt_payload(path), now=SURICATA_NOW),
        local_fetch=fetcher_result(path),
    )


def suricata_evidence_and_gate():
    evidence = evaluate_suricata_eve_json(
        {"event_type": "alert", "alert": {"severity": 1, "signature": "Low", "category": "Policy"}},
        threshold=0,
    )
    gate = evaluate_suricata_policy_gate(
        evidence,
        {"policy_version": "USBAY-SURICATA-002", "severity_threshold": 2, "action_on_threshold_exceeded": "BLOCK"},
    )
    return evidence, gate


def aggregate(tmp_path: Path, receipt=None, finalizer="default"):
    path = rule_file(tmp_path)
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, gate = suricata_evidence_and_gate()
    resolved_finalizer = finalizer_result(path) if finalizer == "default" else finalizer
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
        suricata_rule_source_fetcher=fetcher_result(path),
        suricata_fetch_receipt=receipt,
        suricata_fetch_finalizer=resolved_finalizer,
        suricata_live_fetcher_gate=live_fetcher_gate(tmp_path),
        suricata_live_network_fetch=live_network_fetch_result(tmp_path),
        suricata_publication_connector=publication_connector_result(tmp_path),
    )


def test_valid_fetch_receipt_passes(tmp_path: Path) -> None:
    result = valid_receipt_result(tmp_path)

    assert result.approved is True
    assert result.reason == "SURICATA_FETCH_RECEIPT_APPROVED"
    assert result.evidence_hash.startswith("sha256:")


def test_missing_source_id_fails(tmp_path: Path) -> None:
    result = validate_suricata_fetch_receipt(receipt_payload(rule_file(tmp_path), source_id=""), now=SURICATA_NOW)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_SOURCE_MISSING"


def test_missing_or_invalid_registry_hash_fails(tmp_path: Path) -> None:
    result = validate_suricata_fetch_receipt(receipt_payload(rule_file(tmp_path), source_registry_hash="bad"), now=SURICATA_NOW)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_REGISTRY_HASH_INVALID"


def test_missing_bundle_hash_fails(tmp_path: Path) -> None:
    result = validate_suricata_fetch_receipt(receipt_payload(rule_file(tmp_path), rule_bundle_hash=""), now=SURICATA_NOW)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_BUNDLE_HASH_INVALID"


def test_missing_trust_anchor_hash_fails(tmp_path: Path) -> None:
    result = validate_suricata_fetch_receipt(receipt_payload(rule_file(tmp_path), trust_anchor_hash=""), now=SURICATA_NOW)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_TRUST_ANCHOR_HASH_INVALID"


def test_stale_fetched_at_fails(tmp_path: Path) -> None:
    result = validate_suricata_fetch_receipt(
        receipt_payload(rule_file(tmp_path), fetched_at="2026-06-20T00:00:00Z", freshness_window_seconds=60),
        now=SURICATA_NOW,
    )

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_STALE"


def test_missing_human_approval_fails(tmp_path: Path) -> None:
    result = validate_suricata_fetch_receipt(receipt_payload(rule_file(tmp_path), human_approval_id=""), now=SURICATA_NOW)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_HUMAN_APPROVAL_MISSING"


def test_malformed_receipt_fails(tmp_path: Path) -> None:
    result = validate_suricata_fetch_receipt(receipt_payload(rule_file(tmp_path), fetched_at="not-a-date"), now=SURICATA_NOW)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_MALFORMED"


def test_hash_mismatch_fails(tmp_path: Path) -> None:
    payload = receipt_payload(rule_file(tmp_path))
    payload["fetch_receipt_hash"] = hash_payload("different")

    result = validate_suricata_fetch_receipt(payload, now=SURICATA_NOW)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_HASH_MISMATCH"


def test_runtime_aggregator_blocks_invalid_receipt(tmp_path: Path) -> None:
    result = aggregate(tmp_path, receipt=None, finalizer=finalizer_result(rule_file(tmp_path)))

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_FETCH_RECEIPT_MISSING"


def test_runtime_aggregator_allows_with_receipt(tmp_path: Path) -> None:
    receipt = valid_receipt_result(tmp_path)
    result = aggregate(tmp_path, receipt=receipt)

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["suricata_fetch_receipt_hash"] == receipt.evidence_hash


def test_receipt_output_does_not_include_raw_rules(tmp_path: Path) -> None:
    receipt = valid_receipt_result(tmp_path)
    rendered = json.dumps(receipt.to_dict(), sort_keys=True)

    assert RULE_CONTENT not in rendered
    assert "USBAY receipt test" not in rendered
