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
from publication.suricata_fetch_receipt import suricata_fetch_receipt_hash, validate_suricata_fetch_receipt
from publication.suricata_fetch_receipt_finalizer import finalize_suricata_fetch_receipt
from publication.suricata_live_fetcher_gate import validate_suricata_live_fetcher_gate
from publication.suricata_live_network_fetcher import LiveFetchTransportResponse, fetch_suricata_live_eve_json
from publication.suricata_publication_connector import SuricataPublicationConnectorResponse, publish_suricata_governance_evidence
from publication.suricata_policy_gate import evaluate_suricata_policy_gate
from publication.suricata_policy_manifest import suricata_policy_evidence_hash
from publication.suricata_policy_registry import SuricataPolicyRegistry
from publication.suricata_rule_signature import expected_rule_signature_hash, verify_suricata_rule_signature
from publication.suricata_rule_source_fetcher import LocalRuleSourceFetchRequest, evaluate_local_rule_source_fetch
from publication.suricata_rule_source_registry import SuricataRuleSourceRecord, SuricataRuleSourceRegistry
from publication.suricata_source_replacement_flow import validate_suricata_source_replacement_flow
from publication.suricata_trust_anchor_store import SuricataTrustAnchorStore, finalize_suricata_trust_anchor, suricata_trust_anchor_record_hash
from test_suricata_external_signing_authority import signing_authority_result


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "policy" / "publication" / "publication_registry_record.example.json"
SCHEMA_PATH = ROOT / "policy" / "publication" / "publication_registry_schema.json"
CLASSIFICATION_POLICY_PATH = ROOT / "policy" / "publication" / "publication_classification_policy.json"
APPROVAL_POLICY_PATH = ROOT / "policy" / "publication" / "publication_approval_policy.json"
NOW = datetime.fromisoformat("2026-06-25T00:00:00+00:00")
SURICATA_NOW = datetime.fromisoformat("2026-06-27T00:00:00+00:00")
CURRENT_RULE = 'alert http any any -> any any (msg:"current"; sid:1000004; rev:1;)'
CANDIDATE_RULE = 'alert http any any -> any any (msg:"candidate"; sid:1000005; rev:1;)'


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


def write_rule(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def rule_bundle_hash(path: Path) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def source_record(policy_version: str = "2026.06.27") -> dict[str, object]:
    return {
        "approved_source_id": "suricata-source-managed",
        "source_name": "Managed Suricata Rules",
        "source_uri_hash": hash_payload("https://rules.invalid/suricata"),
        "approved_public_key_hash": hash_payload("suricata-public-key"),
        "approved_policy_version": policy_version,
        "max_age_seconds": 86400,
        "revoked": False,
        "human_approval_id": "approval-suricata-source-001",
    }


def source_registry_result(policy_version: str = "2026.06.27"):
    return SuricataRuleSourceRegistry([source_record(policy_version)]).validate_source(
        approved_source_id="suricata-source-managed",
        policy_version=policy_version,
    )


def rule_signature_result(path: Path, policy_version: str = "2026.06.27"):
    source = source_record(policy_version)
    registry = source_registry_result(policy_version)
    public_key_hash = hash_payload("suricata-public-key")
    bundle_hash = rule_bundle_hash(path)
    return verify_suricata_rule_signature(
        metadata={
            "approved_source_id": "suricata-source-managed",
            "policy_version": policy_version,
            "rule_bundle_hash": bundle_hash,
            "public_key_hash": public_key_hash,
            "signature_hash": expected_rule_signature_hash(
                rule_bundle_hash=bundle_hash,
                public_key_hash=public_key_hash,
                policy_version=policy_version,
            ),
            "generated_at": "2026-06-26T12:00:00Z",
            "rule_count": 1,
        },
        source_record=SuricataRuleSourceRecord.from_dict(source),
        source_registry_result=registry,
        now=SURICATA_NOW,
    )


def trust_anchor_result(policy_version: str = "2026.06.27", revoked: bool = False):
    fingerprint = hash_payload("suricata-public-key")
    record = {
        "anchor_id": "suricata-anchor-managed",
        "issuer": "USBAY Suricata Governance",
        "public_key_fingerprint": fingerprint,
        "status": "revoked" if revoked else "approved",
        "approved_by_human": True,
        "policy_version": policy_version,
        "created_at": "2026-06-26T00:00:00Z",
        "evidence_hash": suricata_trust_anchor_record_hash(
            anchor_id="suricata-anchor-managed",
            issuer="USBAY Suricata Governance",
            public_key_fingerprint=fingerprint,
            status="revoked" if revoked else "approved",
            approved_by_human=True,
            policy_version=policy_version,
            created_at="2026-06-26T00:00:00Z",
        ),
    }
    return SuricataTrustAnchorStore([record]).validate_anchor(
        anchor_id="suricata-anchor-managed",
        expected_fingerprint=fingerprint,
        policy_version=policy_version,
    )


def trust_anchor_finalizer_result(policy_version: str = "2026.06.27", revoked: bool = False):
    return finalize_suricata_trust_anchor(trust_anchor_result(policy_version, revoked))


def fetch_receipt_result(path: Path, policy_version: str = "2026.06.27", **overrides: object):
    payload: dict[str, object] = {
        "source_id": "suricata-source-managed",
        "source_registry_hash": source_registry_result(policy_version).evidence_hash,
        "rule_bundle_hash": rule_bundle_hash(path),
        "trust_anchor_hash": trust_anchor_finalizer_result(policy_version).evidence_hash,
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


def fetch_finalizer_result(path: Path):
    return finalize_suricata_fetch_receipt(
        source_registry=source_registry_result(),
        source_signature=rule_signature_result(path),
        trust_anchor=trust_anchor_result(),
        trust_anchor_finalizer=trust_anchor_finalizer_result(),
        fetch_receipt=fetch_receipt_result(path),
        local_fetch=local_fetch_result(path),
    )


def replacement_flow(tmp_path: Path, **overrides):
    current = write_rule(tmp_path, "current.rules", CURRENT_RULE)
    candidate = write_rule(tmp_path, "candidate.rules", CANDIDATE_RULE)
    params = {
        "current_fetch_finalizer": fetch_finalizer_result(current),
        "candidate_fetch_receipt": fetch_receipt_result(candidate),
        "candidate_source_registry": source_registry_result(),
        "candidate_signature": rule_signature_result(candidate),
        "trust_anchor": trust_anchor_result(),
        "trust_anchor_finalizer": trust_anchor_finalizer_result(),
        "rollback_plan_id": "rollback-plan-suricata-001",
        "human_approval_id": "approval-suricata-replacement-001",
        "replacement_approved": True,
    }
    params.update(overrides)
    return validate_suricata_source_replacement_flow(**params)


def live_fetcher_gate_result(tmp_path: Path):
    candidate = write_rule(tmp_path, "candidate-live-source-replacement.rules", CANDIDATE_RULE)
    return validate_suricata_live_fetcher_gate(
        policy={
            "policy_version": "2026.06.27",
            "live_fetch_enabled": True,
            "allow_live_network_fetcher": True,
            "human_approval_id": "approval-live-fetcher-001",
            "evaluated_at": "2026-06-27T00:00:00Z",
        },
        source_registry=source_registry_result(),
        trust_anchor=trust_anchor_result(),
        trust_anchor_finalizer=trust_anchor_finalizer_result(),
        fetch_receipt=fetch_receipt_result(candidate),
        replacement_flow=replacement_flow(tmp_path),
    )


def live_network_fetch_result(tmp_path: Path):
    candidate = write_rule(tmp_path, "candidate-live-network-replacement.rules", CANDIDATE_RULE)
    return fetch_suricata_live_eve_json(
        source_url="https://rules.usbay.invalid/eve.json",
        config={
            "enabled": True,
            "allowlist": ["https://rules.usbay.invalid/eve.json"],
            "timeout": 2,
            "max_payload_size": 4096,
            "tls_required": True,
            "verify_certificate": True,
            "retry_count": 0,
            "retry_backoff": 0,
            "policy_version": "2026.06.27",
            "requested_at": "2026-06-27T00:00:00Z",
        },
        trust_anchor=trust_anchor_result(),
        fetch_receipt=fetch_receipt_result(candidate),
        replacement_flow=replacement_flow(tmp_path),
        live_fetcher_gate=live_fetcher_gate_result(tmp_path),
        transport=lambda _url, _timeout: LiveFetchTransportResponse(
            status_code=200,
            body=json.dumps(
                {
                    "event_type": "alert",
                    "alert": {"severity": 4, "signature": "Allowed", "category": "Policy"},
                    "src_ip": "192.0.2.10",
                    "dest_ip": "198.51.100.20",
                    "http": {"hostname": "example.com", "http_user_agent": "Mozilla/5.0"},
                    "payload": "payload-bytes",
                    "username": "alice",
                }
            ).encode("utf-8"),
            certificate_fingerprint=trust_anchor_result().public_key_fingerprint,
            certificate_valid=True,
            fetched_at="2026-06-27T00:00:00Z",
        ),
    )


def publication_connector_result(tmp_path: Path):
    live_fetch = live_network_fetch_result(tmp_path)
    return publish_suricata_governance_evidence(
        endpoint_url="https://gateway.usbay.invalid/suricata/evidence",
        config={
            "enabled": True,
            "allowlist": ["https://gateway.usbay.invalid/suricata/evidence"],
            "timeout": 2,
            "retry_count": 0,
            "tls_required": True,
            "verify_certificate": True,
            "policy_version": live_fetch.policy_version,
            "trust_fingerprint": live_fetch.trust_anchor_fingerprint,
            "expected_evidence_hash": live_fetch.evidence_hash,
            "max_timestamp_age_seconds": 300,
            "now": "2026-06-27T00:00:00Z",
            "trust_provider": {
                "provider_type": "LOCAL_TEST_PROVIDER",
                "provider_id": "local-offline-suricata-provider",
                "configured": True,
                "human_approved": True,
                "provider_reference_hash": hash_payload("local-offline-suricata-provider"),
                "policy_version": live_fetch.policy_version,
            },
        },
        live_network_fetch=live_fetch,
        nonce="nonce-suricata-016",
        timestamp="2026-06-27T00:00:00Z",
        seen_nonces=(),
        transport=lambda _url, _body, _timeout: SuricataPublicationConnectorResponse(
            status_code=202,
            body=json.dumps({"accepted": True, "accepted_evidence_hash": live_fetch.evidence_hash}).encode("utf-8"),
            certificate_fingerprint=live_fetch.trust_anchor_fingerprint,
            certificate_valid=True,
            responded_at="2026-06-27T00:00:00Z",
        ),
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


def aggregate(tmp_path: Path, replacement=None):
    current = write_rule(tmp_path, "current.rules", CURRENT_RULE)
    candidate = write_rule(tmp_path, "candidate.rules", CANDIDATE_RULE)
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
        suricata_rule_source=rule_signature_result(candidate),
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
        suricata_live_rule_source_enabled=True,
        suricata_rule_source_fetcher=local_fetch_result(candidate),
        suricata_fetch_receipt=fetch_receipt_result(candidate),
        suricata_fetch_finalizer=fetch_finalizer_result(candidate),
        suricata_replacement_mode_enabled=True,
        suricata_replacement_flow=replacement,
        suricata_live_fetcher_gate=live_fetcher_gate_result(tmp_path),
        suricata_live_network_fetch=live_network_fetch_result(tmp_path),
        suricata_publication_connector=publication_connector_result(tmp_path),
    )


def test_replacement_flow_passes(tmp_path: Path) -> None:
    result = replacement_flow(tmp_path)

    assert result.approved is True
    assert result.decision == "ALLOW"
    assert result.replacement_flow_hash.startswith("sha256:")


def test_current_source_proof_missing_fails(tmp_path: Path) -> None:
    result = replacement_flow(tmp_path, current_fetch_finalizer=None)

    assert result.approved is False
    assert result.reason == "SURICATA_REPLACEMENT_CURRENT_PROOF_MISSING"


def test_candidate_source_proof_missing_fails(tmp_path: Path) -> None:
    result = replacement_flow(tmp_path, candidate_source_registry=None)

    assert result.approved is False
    assert result.reason == "SURICATA_REPLACEMENT_CANDIDATE_REGISTRY_MISSING"


def test_trust_anchor_revoked_fails(tmp_path: Path) -> None:
    result = replacement_flow(tmp_path, trust_anchor=trust_anchor_result(revoked=True))

    assert result.approved is False
    assert result.reason == "SURICATA_TRUST_ANCHOR_REVOKED"


def test_policy_version_mismatch_fails(tmp_path: Path) -> None:
    candidate = write_rule(tmp_path, "candidate-policy.rules", CANDIDATE_RULE)
    result = replacement_flow(tmp_path, candidate_signature=rule_signature_result(candidate, policy_version="2026.06.01"))

    assert result.approved is False
    assert result.reason == "SURICATA_REPLACEMENT_POLICY_MISMATCH"


def test_rule_bundle_hash_mismatch_requires_explicit_replacement_approval(tmp_path: Path) -> None:
    result = replacement_flow(tmp_path, replacement_approved=False)

    assert result.approved is False
    assert result.reason == "SURICATA_REPLACEMENT_APPROVAL_REQUIRED"


def test_missing_rollback_plan_id_fails(tmp_path: Path) -> None:
    result = replacement_flow(tmp_path, rollback_plan_id="")

    assert result.approved is False
    assert result.reason == "SURICATA_REPLACEMENT_ROLLBACK_PLAN_MISSING"


def test_missing_human_approval_fails(tmp_path: Path) -> None:
    result = replacement_flow(tmp_path, human_approval_id="")

    assert result.approved is False
    assert result.reason == "SURICATA_REPLACEMENT_HUMAN_APPROVAL_MISSING"


def test_stale_candidate_receipt_fails(tmp_path: Path) -> None:
    candidate = write_rule(tmp_path, "candidate-stale.rules", CANDIDATE_RULE)
    stale = fetch_receipt_result(candidate, fetched_at="2026-06-20T00:00:00Z", freshness_window_seconds=60)
    result = replacement_flow(tmp_path, candidate_fetch_receipt=stale)

    assert result.approved is False
    assert result.reason == "SURICATA_FETCH_RECEIPT_STALE"


def test_malformed_replacement_object_fails(tmp_path: Path) -> None:
    candidate = write_rule(tmp_path, "candidate-malformed.rules", CANDIDATE_RULE)
    malformed_signature = rule_signature_result(candidate)
    malformed_signature = type(malformed_signature)(
        approved=malformed_signature.approved,
        approved_source_id=malformed_signature.approved_source_id,
        policy_version=malformed_signature.policy_version,
        evidence_hash="bad",
        rule_bundle_hash=malformed_signature.rule_bundle_hash,
        reason=malformed_signature.reason,
    )
    result = replacement_flow(tmp_path, candidate_signature=malformed_signature)

    assert result.approved is False
    assert result.reason == "SURICATA_REPLACEMENT_MALFORMED"


def test_runtime_aggregator_blocks_missing_replacement_flow(tmp_path: Path) -> None:
    result = aggregate(tmp_path, replacement=None)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_REPLACEMENT_FLOW_MISSING"


def test_runtime_aggregator_allows_with_replacement_flow(tmp_path: Path) -> None:
    replacement = replacement_flow(tmp_path)
    result = aggregate(tmp_path, replacement=replacement)

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["replacement_flow_hash"] == replacement.replacement_flow_hash
    assert result.audit.evidence_hashes["replacement_decision"] == "ALLOW"


def test_final_report_never_leaks_raw_suricata_content(tmp_path: Path) -> None:
    current = write_rule(tmp_path, "current-report.rules", CURRENT_RULE)
    candidate = write_rule(tmp_path, "candidate-report.rules", CANDIDATE_RULE)
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, gate = suricata_evidence_and_gate()
    replacement = replacement_flow(tmp_path)

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
        suricata_rule_source=rule_signature_result(candidate),
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
        suricata_live_rule_source_enabled=True,
        suricata_rule_source_fetcher=local_fetch_result(candidate),
        suricata_fetch_receipt=fetch_receipt_result(candidate),
        suricata_fetch_finalizer=fetch_finalizer_result(candidate),
        suricata_replacement_mode_enabled=True,
        suricata_replacement_flow=replacement,
        suricata_live_fetcher_gate=live_fetcher_gate_result(tmp_path),
        suricata_live_network_fetch=live_network_fetch_result(tmp_path),
        suricata_publication_connector=publication_connector_result(tmp_path),
    )
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert report.report_complete is True
    for raw_value in (
        CURRENT_RULE,
        CANDIDATE_RULE,
        "https://rules.invalid/suricata",
        "192.0.2.10",
        "198.51.100.20",
        "example.com",
        "payload-bytes",
        "Mozilla/5.0",
        "alice",
    ):
        assert raw_value not in rendered
