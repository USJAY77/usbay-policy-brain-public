from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from publication.models import BlockReason, hash_payload
from publication.runtime_aggregator import aggregate_runtime_publication_decision, aggregate_runtime_publication_report
from publication.suricata_live_network_fetcher import LiveFetchTransportResponse, fetch_suricata_live_eve_json
from test_suricata_external_signing_authority import signing_authority_result
from test_suricata_live_fetcher_gate import (
    eve_payload,
    gate,
    live_fetch_config,
    live_network_fetch_result,
    publication_connector_result,
    transport_response,
)
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
from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.policy_bundle_readiness import evaluate_policy_bundle_readiness
from publication.policy_bundle_validator import load_publication_policy_bundle, validate_policy_bundle
from publication.registry_store import load_json_file


SOURCE_URL = "https://rules.usbay.invalid/eve.json"


def fetch(tmp_path: Path, **overrides):
    candidate = write_rule(tmp_path, "candidate-live-network-test.rules", CANDIDATE_RULE)
    params = {
        "source_url": SOURCE_URL,
        "config": live_fetch_config(),
        "trust_anchor": trust_anchor_result(),
        "fetch_receipt": fetch_receipt_result(candidate),
        "replacement_flow": replacement_flow(tmp_path),
        "live_fetcher_gate": gate(tmp_path),
        "transport": lambda _url, _timeout: transport_response(),
    }
    params.update(overrides)
    return fetch_suricata_live_eve_json(**params)


def aggregate(tmp_path: Path, *, live_fetch=None, connector="default", policy_gate_override=None):
    candidate = write_rule(tmp_path, "candidate-live-network-aggregate.rules", CANDIDATE_RULE)
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, policy_gate = suricata_evidence_and_gate()
    replacement = replacement_flow(tmp_path)
    resolved_connector = publication_connector_result(tmp_path, live_fetch) if connector == "default" and live_fetch is not None else connector
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
        suricata_policy_gate=policy_gate_override or policy_gate,
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
        suricata_live_fetcher_gate=gate(tmp_path),
        suricata_live_network_fetch=live_fetch,
        suricata_publication_connector=resolved_connector,
    )


def test_approved_fetch_passes(tmp_path: Path) -> None:
    result = fetch(tmp_path)

    assert result.approved is True
    assert result.reason == "SURICATA_LIVE_NETWORK_FETCH_APPROVED"
    assert result.evidence_hash.startswith("sha256:")
    assert result.bundle_hash.startswith("sha256:")


def test_http_endpoint_blocks(tmp_path: Path) -> None:
    result = fetch(tmp_path, source_url="http://rules.usbay.invalid/eve.json")

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_HTTPS_REQUIRED"


def test_expired_certificate_blocks(tmp_path: Path) -> None:
    result = fetch(tmp_path, transport=lambda _url, _timeout: transport_response(certificate_expired=True))

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_CERT_EXPIRED"


def test_self_signed_certificate_blocks(tmp_path: Path) -> None:
    result = fetch(tmp_path, transport=lambda _url, _timeout: transport_response(certificate_self_signed=True))

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_CERT_SELF_SIGNED"


def test_hostname_mismatch_blocks(tmp_path: Path) -> None:
    result = fetch(tmp_path, transport=lambda _url, _timeout: transport_response(hostname_matches=False))

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_CERT_HOSTNAME_MISMATCH"


def test_timeout_blocks(tmp_path: Path) -> None:
    def timed_out(_url, _timeout):
        raise TimeoutError("timeout")

    result = fetch(tmp_path, transport=timed_out)

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_TIMEOUT"


def test_oversized_payload_blocks(tmp_path: Path) -> None:
    result = fetch(tmp_path, config=live_fetch_config(max_payload_size=4))

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_PAYLOAD_TOO_LARGE"


def test_malformed_json_blocks(tmp_path: Path) -> None:
    result = fetch(tmp_path, transport=lambda _url, _timeout: transport_response(body=b"{not-json"))

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_JSON_MALFORMED"


def test_unexpected_schema_blocks(tmp_path: Path) -> None:
    result = fetch(tmp_path, transport=lambda _url, _timeout: transport_response(body=json.dumps({"event_type": "stats"}).encode("utf-8")))

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_UNEXPECTED_SCHEMA"


def test_missing_registry_blocks(tmp_path: Path) -> None:
    result = fetch(tmp_path, live_fetcher_gate=None)

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_GATE_INVALID"


def test_missing_signature_blocks_runtime(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = aggregate(tmp_path, live_fetch=live_fetch)
    assert result.publish_allowed is True

    candidate = write_rule(tmp_path, "candidate-missing-signature.rules", CANDIDATE_RULE)
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, policy_gate = suricata_evidence_and_gate()
    blocked = aggregate_runtime_publication_decision(
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
        suricata_rule_source=None,
        suricata_trust_anchor=trust_anchor_result(),
        suricata_trust_anchor_finalizer=trust_anchor_finalizer_result(),
        suricata_signing_authority=signing_authority_result(),
        suricata_live_rule_source_enabled=True,
        suricata_rule_source_fetcher=local_fetch_result(candidate),
        suricata_fetch_receipt=fetch_receipt_result(candidate),
        suricata_fetch_finalizer=fetch_finalizer_result(candidate),
        suricata_replacement_mode_enabled=True,
        suricata_replacement_flow=replacement_flow(tmp_path),
        suricata_live_fetcher_gate=gate(tmp_path),
        suricata_live_network_fetch=live_fetch,
        suricata_publication_connector=publication_connector_result(tmp_path, live_fetch),
    )
    assert blocked.publish_allowed is False
    assert blocked.audit.evidence_hashes["suricata_reason"] == "SURICATA_RULE_SOURCE_MISSING"


def test_missing_receipt_blocks(tmp_path: Path) -> None:
    result = fetch(tmp_path, fetch_receipt=None)

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_FETCH_RECEIPT_INVALID"


def test_missing_trust_anchor_blocks(tmp_path: Path) -> None:
    result = fetch(tmp_path, trust_anchor=None)

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_TRUST_ANCHOR_INVALID"


def test_policy_reject_blocks_runtime(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    evidence, gate_result = suricata_evidence_and_gate()
    rejected_gate = replace(gate_result, approved=False, reason="SURICATA_POLICY_THRESHOLD_BLOCKED")
    result = aggregate(tmp_path, live_fetch=live_fetch, policy_gate_override=rejected_gate)

    assert evidence.accepted is True
    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.NETWORK_IDS_EVIDENCE_BLOCKED


def test_replacement_reject_blocks(tmp_path: Path) -> None:
    rejected = replace(replacement_flow(tmp_path), approved=False, reason="SURICATA_REPLACEMENT_REJECTED")
    result = fetch(tmp_path, replacement_flow=rejected)

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_REPLACEMENT_FLOW_INVALID"


def test_hash_mismatch_blocks(tmp_path: Path) -> None:
    result = fetch(
        tmp_path,
        transport=lambda _url, _timeout: transport_response(certificate_fingerprint=hash_payload("wrong-cert")),
    )

    assert result.approved is False
    assert result.reason == "SURICATA_LIVE_NETWORK_CERT_FINGERPRINT_MISMATCH"


def test_runtime_aggregator_blocks_missing_live_network_fetch(tmp_path: Path) -> None:
    result = aggregate(tmp_path, live_fetch=None, connector=None)

    assert result.publish_allowed is False
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_LIVE_NETWORK_FETCH_MISSING"


def test_runtime_aggregator_allows_with_complete_governance_chain(tmp_path: Path) -> None:
    result = aggregate(tmp_path, live_fetch=live_network_fetch_result(tmp_path))

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["suricata_live_network_decision"] == "ALLOW"


def test_deterministic_evidence_and_bundle_hash(tmp_path: Path) -> None:
    first = fetch(tmp_path)
    second = fetch(tmp_path)

    assert first.evidence_hash == second.evidence_hash
    assert first.bundle_hash == second.bundle_hash


def test_final_report_exposes_only_allowed_live_fetch_fields(tmp_path: Path) -> None:
    candidate = write_rule(tmp_path, "candidate-live-network-report.rules", CANDIDATE_RULE)
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, policy_gate = suricata_evidence_and_gate()
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
        suricata_replacement_flow=replacement_flow(tmp_path),
        suricata_live_fetcher_gate=gate(tmp_path),
        suricata_live_network_fetch=live_fetch,
        suricata_publication_connector=publication_connector_result(tmp_path, live_fetch),
    )
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert report.report_complete is True
    assert report.suricata_live_network_fetch_hash == live_fetch.evidence_hash
    assert report.suricata_live_network_bundle_hash == live_fetch.bundle_hash
    assert report.suricata_live_network_timestamp == "2026-06-27T00:00:00Z"
    assert report.suricata_live_network_policy_version == "2026.06.27"
    assert report.suricata_live_network_trust_fingerprint == trust_anchor_result().public_key_fingerprint
    assert report.suricata_live_network_decision == "ALLOW"
    assert report.suricata_live_network_reason == "SURICATA_LIVE_NETWORK_FETCH_APPROVED"
    for raw_value in (
        json.dumps(eve_payload(), sort_keys=True),
        CANDIDATE_RULE,
        "https://rules.usbay.invalid/eve.json",
        "192.0.2.10",
        "198.51.100.20",
        "example.com",
        "payload-bytes",
        "Mozilla/5.0",
        "alice",
    ):
        assert raw_value not in rendered
