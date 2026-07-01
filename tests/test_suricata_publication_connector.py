from __future__ import annotations

import json
from pathlib import Path

from publication.models import BlockReason, hash_payload
from publication.runtime_aggregator import aggregate_runtime_publication_decision, aggregate_runtime_publication_report
from publication.suricata_publication_connector import (
    CONNECTOR_VERSION,
    FileBackedNonceStore,
    SuricataPublicationConnectorResponse,
    publish_suricata_governance_evidence,
)
from test_suricata_external_signing_authority import signing_authority_result
from test_suricata_live_fetcher_gate import gate
from test_suricata_live_network_fetcher import live_network_fetch_result
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
    suricata_evidence_and_gate,
    trust_anchor_finalizer_result,
    trust_anchor_result,
    write_rule,
)
from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.policy_bundle_readiness import evaluate_policy_bundle_readiness
from publication.policy_bundle_validator import load_publication_policy_bundle, validate_policy_bundle
from publication.registry_store import load_json_file


ENDPOINT = "https://gateway.usbay.invalid/suricata/evidence"
TIMESTAMP = "2026-06-27T00:00:00Z"
NONCE = "nonce-suricata-016"


def connector_config(live_fetch, **overrides: object) -> dict[str, object]:
    config: dict[str, object] = {
        "enabled": True,
        "allowlist": [ENDPOINT],
        "timeout": 2,
        "retry_count": 0,
        "tls_required": True,
        "verify_certificate": True,
        "policy_version": live_fetch.policy_version,
        "trust_fingerprint": live_fetch.trust_anchor_fingerprint,
        "expected_evidence_hash": live_fetch.evidence_hash,
        "max_timestamp_age_seconds": 300,
        "now": TIMESTAMP,
        "trust_provider": {
            "provider_type": "LOCAL_TEST_PROVIDER",
            "provider_id": "local-offline-suricata-provider",
            "configured": True,
            "human_approved": True,
            "provider_reference_hash": hash_payload("local-offline-suricata-provider"),
            "policy_version": live_fetch.policy_version,
        },
    }
    config.update(overrides)
    if "policy_version" in overrides and "trust_provider" not in overrides and isinstance(config["trust_provider"], dict):
        config["trust_provider"] = {**config["trust_provider"], "policy_version": str(config["policy_version"])}
    return config


def connector_response(live_fetch, **overrides):
    payload = {"accepted": True, "accepted_evidence_hash": live_fetch.evidence_hash}
    response = {
        "status_code": 202,
        "body": json.dumps(payload).encode("utf-8"),
        "certificate_fingerprint": live_fetch.trust_anchor_fingerprint,
        "certificate_valid": True,
        "certificate_expired": False,
        "certificate_self_signed": False,
        "hostname_matches": True,
        "responded_at": TIMESTAMP,
    }
    response.update(overrides)
    return SuricataPublicationConnectorResponse(**response)


def connector_result(tmp_path: Path, live_fetch=None, **overrides):
    live_fetch = live_fetch or live_network_fetch_result(tmp_path)
    params = {
        "endpoint_url": ENDPOINT,
        "config": connector_config(live_fetch),
        "live_network_fetch": live_fetch,
        "nonce": NONCE,
        "timestamp": TIMESTAMP,
        "seen_nonces": (),
        "transport": lambda _url, _body, _timeout: connector_response(live_fetch),
    }
    params.update(overrides)
    return publish_suricata_governance_evidence(**params)


def aggregate(tmp_path: Path, connector=None):
    candidate = write_rule(tmp_path, "candidate-connector-aggregate.rules", CANDIDATE_RULE)
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, policy_gate = suricata_evidence_and_gate()
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
        suricata_replacement_flow=replacement_flow(tmp_path),
        suricata_live_fetcher_gate=gate(tmp_path),
        suricata_live_network_fetch=live_fetch,
        suricata_publication_connector=connector,
    )


def test_approved_connector_publishes_hash_only_payload(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    captured: dict[str, object] = {}

    def transport(url, body, timeout):
        captured["url"] = url
        captured["body"] = json.loads(body.decode("utf-8"))
        captured["timeout"] = timeout
        return connector_response(live_fetch)

    result = connector_result(tmp_path, live_fetch=live_fetch, transport=transport)

    assert result.approved is True
    assert result.reason == "SURICATA_CONNECTOR_PUBLICATION_APPROVED"
    assert captured["body"] == {
        "evidence_hash": live_fetch.evidence_hash,
        "policy_version": live_fetch.policy_version,
        "trust_fingerprint": live_fetch.trust_anchor_fingerprint,
        "decision": live_fetch.decision,
        "reason": live_fetch.reason,
        "timestamp": TIMESTAMP,
        "nonce": NONCE,
        "connector_version": CONNECTOR_VERSION,
    }


def test_missing_endpoint_blocks(tmp_path: Path) -> None:
    result = connector_result(tmp_path, endpoint_url="")
    assert result.reason == "SURICATA_CONNECTOR_ENDPOINT_MISSING"


def test_connector_disabled_blocks(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = connector_result(tmp_path, live_fetch=live_fetch, config=connector_config(live_fetch, enabled=False))
    assert result.reason == "SURICATA_CONNECTOR_DISABLED"


def test_http_endpoint_blocks(tmp_path: Path) -> None:
    result = connector_result(tmp_path, endpoint_url="http://gateway.usbay.invalid/suricata/evidence")
    assert result.reason == "SURICATA_CONNECTOR_HTTPS_REQUIRED"


def test_unapproved_endpoint_blocks(tmp_path: Path) -> None:
    result = connector_result(tmp_path, endpoint_url="https://unknown.usbay.invalid/suricata/evidence")
    assert result.reason == "SURICATA_CONNECTOR_ENDPOINT_NOT_ALLOWED"


def test_missing_certificate_fingerprint_blocks(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = connector_result(tmp_path, live_fetch=live_fetch, transport=lambda _u, _b, _t: connector_response(live_fetch, certificate_fingerprint=""))
    assert result.reason == "SURICATA_CONNECTOR_CERT_FINGERPRINT_MISSING"


def test_trust_fingerprint_mismatch_blocks(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = connector_result(tmp_path, live_fetch=live_fetch, transport=lambda _u, _b, _t: connector_response(live_fetch, certificate_fingerprint=hash_payload("wrong")))
    assert result.reason == "SURICATA_CONNECTOR_TRUST_FINGERPRINT_MISMATCH"


def test_policy_mismatch_blocks(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = connector_result(tmp_path, live_fetch=live_fetch, config=connector_config(live_fetch, policy_version="2026.01.01"))
    assert result.reason == "SURICATA_CONNECTOR_POLICY_MISMATCH"


def test_evidence_hash_mismatch_blocks(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = connector_result(tmp_path, live_fetch=live_fetch, config=connector_config(live_fetch, expected_evidence_hash=hash_payload("wrong")))
    assert result.reason == "SURICATA_CONNECTOR_EVIDENCE_HASH_MISMATCH"


def test_replayed_nonce_blocks(tmp_path: Path) -> None:
    result = connector_result(tmp_path, seen_nonces=(NONCE,))
    assert result.reason == "SURICATA_CONNECTOR_REPLAYED_NONCE"


def test_file_backed_nonce_store_rejects_replay(tmp_path: Path) -> None:
    store = FileBackedNonceStore(tmp_path / "nonce-store.json")

    first = connector_result(tmp_path, nonce_store=store)
    second = connector_result(tmp_path, nonce_store=store)

    assert first.approved is True
    assert second.reason == "SURICATA_CONNECTOR_REPLAYED_NONCE"


def test_stale_timestamp_blocks(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = connector_result(
        tmp_path,
        live_fetch=live_fetch,
        timestamp="2026-06-26T23:00:00Z",
        config=connector_config(live_fetch, now=TIMESTAMP, max_timestamp_age_seconds=60),
    )
    assert result.reason == "SURICATA_CONNECTOR_TIMESTAMP_STALE"


def test_timeout_blocks(tmp_path: Path) -> None:
    def timeout(_url, _body, _timeout):
        raise TimeoutError("timeout")

    result = connector_result(tmp_path, transport=timeout)
    assert result.reason == "SURICATA_CONNECTOR_TIMEOUT"


def test_missing_trust_provider_blocks(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = connector_result(tmp_path, live_fetch=live_fetch, config=connector_config(live_fetch, trust_provider=None))
    assert result.reason == "SURICATA_CONNECTOR_TRUST_PROVIDER_MISSING"


def test_missing_trust_provider_approval_blocks(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    provider = dict(connector_config(live_fetch)["trust_provider"])
    provider["human_approved"] = False
    result = connector_result(tmp_path, live_fetch=live_fetch, config=connector_config(live_fetch, trust_provider=provider))
    assert result.reason == "SURICATA_CONNECTOR_TRUST_PROVIDER_NOT_APPROVED"


def test_malformed_response_blocks(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = connector_result(tmp_path, live_fetch=live_fetch, transport=lambda _u, _b, _t: connector_response(live_fetch, body=b"{bad-json"))
    assert result.reason == "SURICATA_CONNECTOR_RESPONSE_MALFORMED"


def test_5xx_response_blocks(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = connector_result(tmp_path, live_fetch=live_fetch, transport=lambda _u, _b, _t: connector_response(live_fetch, status_code=503))
    assert result.reason == "SURICATA_CONNECTOR_GATEWAY_5XX"


def test_raw_suricata_data_leakage_blocked_by_payload_contract(tmp_path: Path) -> None:
    live_fetch = live_network_fetch_result(tmp_path)
    result = connector_result(tmp_path, live_fetch=live_fetch)
    rendered = json.dumps(result.to_dict(), sort_keys=True)

    assert result.approved is True
    for raw_value in (
        CANDIDATE_RULE,
        "192.0.2.10",
        "198.51.100.20",
        "example.com",
        "payload-bytes",
        "Mozilla/5.0",
        "alice",
        "https://rules.usbay.invalid/eve.json",
        ENDPOINT,
        "BEGIN CERTIFICATE",
        "PRIVATE KEY",
        "secret-token",
    ):
        assert raw_value not in rendered


def test_runtime_aggregator_blocks_malformed_connector_evidence(tmp_path: Path) -> None:
    connector = connector_result(tmp_path)
    malformed = type(connector)(
        approved=True,
        blocked=False,
        decision="ALLOW",
        reason=connector.reason,
        evidence_hash="not-a-sha",
        policy_version=connector.policy_version,
        trust_fingerprint=connector.trust_fingerprint,
        timestamp=connector.timestamp,
        nonce=connector.nonce,
        connector_version=connector.connector_version,
    )

    result = aggregate(tmp_path, connector=malformed)

    assert result.publish_allowed is False
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_PUBLICATION_CONNECTOR_MALFORMED"


def test_runtime_aggregator_blocks_missing_connector(tmp_path: Path) -> None:
    result = aggregate(tmp_path, connector=None)
    assert result.publish_allowed is False
    assert result.audit.evidence_hashes["suricata_reason"] == "SURICATA_PUBLICATION_CONNECTOR_MISSING"


def test_runtime_aggregator_allows_with_approved_connector(tmp_path: Path) -> None:
    connector = connector_result(tmp_path)
    result = aggregate(tmp_path, connector=connector)
    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["suricata_publication_connector_decision"] == "ALLOW"


def test_final_report_exposes_only_connector_allowed_fields(tmp_path: Path) -> None:
    candidate = write_rule(tmp_path, "candidate-connector-report.rules", CANDIDATE_RULE)
    record = example_record()
    policy_bundle_result = validate_policy_bundle(load_publication_policy_bundle())
    evidence, policy_gate = suricata_evidence_and_gate()
    live_fetch = live_network_fetch_result(tmp_path)
    connector = connector_result(tmp_path, live_fetch=live_fetch)
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
        suricata_publication_connector=connector,
    )
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert report.report_complete is True
    assert report.suricata_publication_connector_hash == connector.evidence_hash
    assert report.suricata_publication_connector_policy_version == live_fetch.policy_version
    assert report.suricata_publication_connector_trust_fingerprint == live_fetch.trust_anchor_fingerprint
    assert report.suricata_publication_connector_decision == "ALLOW"
    assert report.suricata_publication_connector_reason == "SURICATA_CONNECTOR_PUBLICATION_APPROVED"
    assert report.suricata_publication_connector_timestamp == TIMESTAMP
    assert report.suricata_publication_connector_nonce == NONCE
    assert report.suricata_publication_connector_version == CONNECTOR_VERSION
    for raw_value in (
        CANDIDATE_RULE,
        "192.0.2.10",
        "198.51.100.20",
        "example.com",
        "payload-bytes",
        "Mozilla/5.0",
        "alice",
        "https://rules.usbay.invalid/eve.json",
    ):
        assert raw_value not in rendered
