from __future__ import annotations

import json
from pathlib import Path

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.models import BlockReason, hash_payload
from publication.policy_bundle_readiness import evaluate_policy_bundle_readiness
from publication.policy_bundle_validator import load_publication_policy_bundle, validate_policy_bundle
from publication.registry_store import load_json_file
from publication.runtime_aggregator import aggregate_runtime_publication_decision, aggregate_runtime_publication_report
from publication.suricata_live_fetcher_gate import validate_suricata_live_fetcher_gate
from publication.suricata_live_network_fetcher import LiveFetchTransportResponse, fetch_suricata_live_eve_json
from publication.suricata_publication_connector import SuricataPublicationConnectorResponse, publish_suricata_governance_evidence
from test_suricata_external_signing_authority import signing_authority_result
from test_suricata_source_replacement_flow import (
    APPROVAL_POLICY_PATH,
    CANDIDATE_RULE,
    CLASSIFICATION_POLICY_PATH,
    NOW,
    SCHEMA_PATH,
    approval,
    example_record,
    fetch_finalizer_result,
    fetch_receipt_result,
    local_fetch_result,
    policy_registry_result,
    replacement_flow,
    rule_signature_result,
    source_registry_result,
    suricata_evidence_and_gate,
    trust_anchor_finalizer_result,
    trust_anchor_result,
    write_rule,
)


def policy(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "policy_version": "2026.06.27",
        "live_fetch_enabled": True,
        "allow_live_network_fetcher": True,
        "human_approval_id": "approval-live-fetcher-001",
        "evaluated_at": "2026-06-27T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def gate(tmp_path: Path, **overrides):
    candidate = write_rule(tmp_path, "candidate-live-gate.rules", CANDIDATE_RULE)
    params = {
        "policy": policy(),
        "source_registry": source_registry_result(),
        "trust_anchor": trust_anchor_result(),
        "trust_anchor_finalizer": trust_anchor_finalizer_result(),
        "fetch_receipt": fetch_receipt_result(candidate),
        "replacement_flow": replacement_flow(tmp_path),
    }
    params.update(overrides)
    return validate_suricata_live_fetcher_gate(**params)


def live_fetch_config(**overrides: object) -> dict[str, object]:
    config: dict[str, object] = {
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
    }
    config.update(overrides)
    return config


def eve_payload() -> dict[str, object]:
    return {
        "event_type": "alert",
        "alert": {"severity": 4, "signature": "Allowed", "category": "Policy"},
        "src_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "http": {"hostname": "example.com", "http_user_agent": "Mozilla/5.0"},
        "payload": "payload-bytes",
        "username": "alice",
    }


def transport_response(body: bytes | None = None, **overrides):
    response = {
        "status_code": 200,
        "body": body if body is not None else json.dumps(eve_payload()).encode("utf-8"),
        "certificate_fingerprint": trust_anchor_result().public_key_fingerprint,
        "certificate_valid": True,
        "certificate_expired": False,
        "certificate_self_signed": False,
        "hostname_matches": True,
        "fetched_at": "2026-06-27T00:00:00Z",
    }
    response.update(overrides)
    return LiveFetchTransportResponse(**response)


def live_network_fetch_result(tmp_path: Path, **overrides):
    candidate = write_rule(tmp_path, "candidate-live-network.rules", CANDIDATE_RULE)
    params = {
        "source_url": "https://rules.usbay.invalid/eve.json",
        "config": live_fetch_config(),
        "trust_anchor": trust_anchor_result(),
        "fetch_receipt": fetch_receipt_result(candidate),
        "replacement_flow": replacement_flow(tmp_path),
        "live_fetcher_gate": gate(tmp_path),
        "transport": lambda _url, _timeout: transport_response(),
    }
    params.update(overrides)
    return fetch_suricata_live_eve_json(**params)


def publication_connector_result(tmp_path: Path, live_fetch=None):
    live_fetch = live_fetch or live_network_fetch_result(tmp_path)
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


def aggregate(tmp_path: Path, live_gate=None):
    candidate = write_rule(tmp_path, "candidate-live-aggregate.rules", CANDIDATE_RULE)
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, policy_gate = suricata_evidence_and_gate()
    replacement = replacement_flow(tmp_path)
    live_fetch = live_network_fetch_result(tmp_path)
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
        suricata_policy_gate=policy_gate,
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
        suricata_live_fetcher_gate=live_gate,
        suricata_live_network_fetch=live_fetch,
        suricata_publication_connector=publication_connector_result(tmp_path, live_fetch),
    )


def test_live_fetch_disabled_by_default_blocks(tmp_path: Path) -> None:
    result = gate(tmp_path, policy={})

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_FETCH_DISABLED"


def test_missing_human_approval_blocks(tmp_path: Path) -> None:
    result = gate(tmp_path, policy=policy(human_approval_id=""))

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_FETCH_HUMAN_APPROVAL_MISSING"


def test_missing_source_registry_blocks(tmp_path: Path) -> None:
    result = gate(tmp_path, source_registry=None)

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_FETCH_SOURCE_REGISTRY_MISSING"


def test_missing_trust_anchor_proof_blocks(tmp_path: Path) -> None:
    result = gate(tmp_path, trust_anchor=None)

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_FETCH_TRUST_ANCHOR_MISSING"


def test_missing_fetch_receipt_blocks(tmp_path: Path) -> None:
    result = gate(tmp_path, fetch_receipt=None)

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_FETCH_RECEIPT_MISSING"


def test_missing_replacement_flow_blocks(tmp_path: Path) -> None:
    result = gate(tmp_path, replacement_flow=None)

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_FETCH_REPLACEMENT_FLOW_MISSING"


def test_policy_flag_disabled_blocks(tmp_path: Path) -> None:
    result = gate(tmp_path, policy=policy(allow_live_network_fetcher=False))

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_FETCH_POLICY_FLAG_DISABLED"


def test_approved_full_chain_passes(tmp_path: Path) -> None:
    result = gate(tmp_path)

    assert result.approved is True
    assert result.decision == "ALLOW"
    assert result.evidence_hash.startswith("sha256:")


def test_runtime_aggregator_blocks_missing_live_fetcher_gate(tmp_path: Path) -> None:
    result = aggregate(tmp_path, live_gate=None)

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_INVALID
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_LIVE_FETCHER_GATE_MISSING"


def test_runtime_aggregator_allows_with_approved_live_fetcher_gate(tmp_path: Path) -> None:
    live_gate = gate(tmp_path)
    result = aggregate(tmp_path, live_gate=live_gate)

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["suricata_live_fetcher_gate_hash"] == live_gate.evidence_hash


def test_final_report_exposes_only_hashes_policy_decision_reason_timestamp(tmp_path: Path) -> None:
    candidate = write_rule(tmp_path, "candidate-live-report.rules", CANDIDATE_RULE)
    live_gate = gate(tmp_path)
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, policy_gate = suricata_evidence_and_gate()
    replacement = replacement_flow(tmp_path)
    live_fetch = live_network_fetch_result(tmp_path)
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
        suricata_policy_gate=policy_gate,
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
        suricata_live_fetcher_gate=live_gate,
        suricata_live_network_fetch=live_fetch,
        suricata_publication_connector=publication_connector_result(tmp_path, live_fetch),
    )
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert report.report_complete is True
    assert report.suricata_live_fetcher_gate_hash == live_gate.evidence_hash
    assert report.suricata_live_fetcher_policy_version == "2026.06.27"
    assert report.suricata_live_fetcher_decision == "ALLOW"
    assert report.suricata_live_fetcher_reason == "SURICATA_LIVE_FETCH_GATE_APPROVED"
    assert report.suricata_live_fetcher_timestamp == "2026-06-27T00:00:00Z"
    assert report.suricata_live_network_decision == "ALLOW"
    assert report.suricata_live_network_reason == "SURICATA_LIVE_NETWORK_FETCH_APPROVED"
    for raw_value in (
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
