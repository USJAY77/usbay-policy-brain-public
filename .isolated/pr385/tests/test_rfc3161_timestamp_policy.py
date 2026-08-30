from __future__ import annotations

from tests.helpers.rfc3161_timestamp_policy import (
    load_timestamp_policy,
    timestamp_queue_overload_evidence,
    valid_timestamp_evidence,
    verify_timestamp_evidence,
)


def test_valid_rfc3161_style_timestamp_evidence_passes() -> None:
    evidence = verify_timestamp_evidence(valid_timestamp_evidence())

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "RFC3161_TIMESTAMP_EVIDENCE_VALID"
    assert evidence["hash_algorithm"] == "sha256"


def test_missing_timestamp_fails_closed() -> None:
    evidence = verify_timestamp_evidence(None)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "RFC3161_TIMESTAMP_MISSING"
    assert evidence["silent_pass"] is False


def test_malformed_timestamp_fails_closed() -> None:
    timestamp = valid_timestamp_evidence()
    timestamp.pop("message_imprint_sha256")

    evidence = verify_timestamp_evidence(timestamp)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "RFC3161_TIMESTAMP_MALFORMED"
    assert evidence["silent_pass"] is False


def test_unsupported_hash_algorithm_fails_closed() -> None:
    timestamp = valid_timestamp_evidence()
    timestamp["hash_algorithm"] = "sha1"

    evidence = verify_timestamp_evidence(timestamp)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "RFC3161_TIMESTAMP_UNSUPPORTED_HASH_ALGORITHM"
    assert evidence["silent_pass"] is False


def test_timestamp_drift_beyond_policy_fails_closed() -> None:
    timestamp = valid_timestamp_evidence()
    timestamp["timestamp_utc"] = "2026-05-25T00:00:00Z"

    evidence = verify_timestamp_evidence(timestamp, observed_at="2026-05-25T00:10:01Z")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "RFC3161_TIMESTAMP_CLOCK_DRIFT_EXCEEDED"
    assert evidence["silent_pass"] is False


def test_unsigned_timestamp_evidence_fails_closed() -> None:
    timestamp = valid_timestamp_evidence()
    timestamp["signature_state"] = "UNSIGNED"

    evidence = verify_timestamp_evidence(timestamp)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "RFC3161_TIMESTAMP_UNSIGNED"
    assert evidence["silent_pass"] is False


def test_placeholder_tsa_authority_is_explicitly_non_production() -> None:
    policy = load_timestamp_policy()
    evidence = verify_timestamp_evidence(valid_timestamp_evidence(policy), policy=policy)

    assert policy["non_production_scaffolding"] is True
    assert policy["placeholder_tsa_authority"]["trust_state"] == "NON_PRODUCTION_PLACEHOLDER"
    assert evidence["placeholder_tsa_authority"] is True
    assert evidence["production_tsa_authority"] is False


def test_timestamp_queue_overload_simulation_produces_fail_closed_evidence() -> None:
    evidence = timestamp_queue_overload_evidence(queue_depth=32, queue_capacity=4)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "RFC3161_TIMESTAMP_QUEUE_OVERLOADED"
    assert evidence["silent_pass"] is False
