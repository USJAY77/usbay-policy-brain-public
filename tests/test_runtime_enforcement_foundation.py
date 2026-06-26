import gateway.app as gateway_app


FIXED_TIMESTAMP = "2026-06-12T00:00:00Z"
REQUIRED_DENY_EVIDENCE_FIELDS = {
    "reason_code",
    "decision_id",
    "nonce_hash",
    "request_hash",
    "policy_hash",
    "policy_version",
    "timestamp",
}


class FakeNonceStore:
    def __init__(self, exists_result=False, error=None):
        self.exists_result = exists_result
        self.error = error

    def exists(self, nonce):
        if self.error:
            raise self.error
        return self.exists_result


def _record():
    return {
        "decision_id": "decision-pb290",
        "nonce_hash": gateway_app.nonce_hash("nonce-pb290"),
        "request_hash": "r" * 64,
        "policy_hash": "p" * 64,
        "policy_version": "policy-v1",
    }


def _payload():
    return {
        "decision_id": "decision-pb290",
        "nonce": "nonce-pb290",
        "policy_version": "policy-v1",
    }


def _assert_fail_closed(result, reason_code):
    assert result["decision"] == gateway_app.RUNTIME_ENFORCEMENT_DENY
    assert result["execution_allowed"] is False
    assert result["reason_code"] == reason_code
    evidence = result["audit_evidence"]
    assert REQUIRED_DENY_EVIDENCE_FIELDS <= set(evidence)
    assert evidence["reason_code"] == reason_code
    assert evidence["decision_id"] == "decision-pb290"
    assert evidence["nonce_hash"] == gateway_app.nonce_hash("nonce-pb290")
    assert evidence["request_hash"] == "r" * 64
    assert evidence["policy_hash"] == "p" * 64
    assert evidence["policy_version"] == "policy-v1"
    assert evidence["timestamp"] == FIXED_TIMESTAMP
    assert len(evidence["audit_hash"]) == 64


def _assert_next_check_only(result):
    assert result["decision"] == gateway_app.RUNTIME_ENFORCEMENT_NEXT_CHECK
    assert result["execution_allowed"] is False
    assert result["reason_code"] == gateway_app.RUNTIME_ENFORCEMENT_OK


def test_nonce_replay_helper_blocks_missing_nonce_with_required_evidence():
    payload = _payload()
    payload["nonce"] = ""

    result = gateway_app.validate_nonce_replay_for_runtime(
        payload,
        _record(),
        nonce_store_adapter=FakeNonceStore(),
        timestamp=FIXED_TIMESTAMP,
    )

    _assert_fail_closed(result, gateway_app.RUNTIME_DENY_NONCE_MISSING)


def test_nonce_replay_helper_blocks_reused_nonce():
    result = gateway_app.validate_nonce_replay_for_runtime(
        _payload(),
        _record(),
        nonce_store_adapter=FakeNonceStore(exists_result=True),
        timestamp=FIXED_TIMESTAMP,
    )

    _assert_fail_closed(result, gateway_app.RUNTIME_DENY_REPLAY_DETECTED)


def test_nonce_replay_helper_blocks_unavailable_store():
    result = gateway_app.validate_nonce_replay_for_runtime(
        _payload(),
        _record(),
        nonce_store_adapter=FakeNonceStore(error=RuntimeError("store_down")),
        timestamp=FIXED_TIMESTAMP,
    )

    _assert_fail_closed(result, gateway_app.RUNTIME_DENY_NONCE_STORE_UNAVAILABLE)


def test_nonce_replay_helper_never_returns_execution_allow():
    result = gateway_app.validate_nonce_replay_for_runtime(
        _payload(),
        _record(),
        nonce_store_adapter=FakeNonceStore(exists_result=False),
        timestamp=FIXED_TIMESTAMP,
    )

    _assert_next_check_only(result)


def test_attestation_freshness_blocks_missing_unverifiable_malformed_future_and_stale_attestations():
    cases = [
        (None, gateway_app.RUNTIME_DENY_ATTESTATION_MISSING),
        ({"attestation_status": "SIGNED", "signature_valid": False}, gateway_app.RUNTIME_DENY_ATTESTATION_UNVERIFIABLE),
        ({"attestation_status": "SIGNED", "signature_valid": True}, gateway_app.RUNTIME_DENY_ATTESTATION_TIMESTAMP_MISSING),
        (
            {"attestation_status": "SIGNED", "signature_valid": True, "deployment_timestamp_utc": "not-a-date"},
            gateway_app.RUNTIME_DENY_ATTESTATION_TIMESTAMP_MALFORMED,
        ),
        (
            {"attestation_status": "SIGNED", "signature_valid": True, "deployment_timestamp_utc": "2026-06-12T00:10:01Z"},
            gateway_app.RUNTIME_DENY_ATTESTATION_TIMESTAMP_INVALID,
        ),
        (
            {"attestation_status": "SIGNED", "signature_valid": True, "deployment_timestamp_utc": "2026-05-01T00:00:00Z"},
            gateway_app.RUNTIME_DENY_ATTESTATION_STALE,
        ),
    ]

    for attestation, reason_code in cases:
        result = gateway_app.validate_attestation_freshness_for_runtime(
            attestation,
            max_age_seconds=14 * 24 * 60 * 60,
            now_epoch=1781222400,
            payload=_payload(),
            record=_record(),
            timestamp=FIXED_TIMESTAMP,
        )
        _assert_fail_closed(result, reason_code)


def test_attestation_freshness_valid_snapshot_is_next_check_only():
    result = gateway_app.validate_attestation_freshness_for_runtime(
        {"attestation_status": "SIGNED", "signature_valid": True, "deployment_timestamp_utc": "2026-06-12T00:00:00Z"},
        max_age_seconds=14 * 24 * 60 * 60,
        now_epoch=1781222400,
        payload=_payload(),
        record=_record(),
        timestamp=FIXED_TIMESTAMP,
    )

    _assert_next_check_only(result)


def test_runtime_revocation_blocks_runtime_state_policy_hash_and_policy_version():
    runtime_revoked = gateway_app.validate_runtime_revocation_state_for_runtime(
        _record(),
        payload=_payload(),
        runtime_state="REVOKED",
        timestamp=FIXED_TIMESTAMP,
    )
    hash_revoked = gateway_app.validate_runtime_revocation_state_for_runtime(
        _record(),
        payload=_payload(),
        revoked_policy_hashes={"p" * 64},
        timestamp=FIXED_TIMESTAMP,
    )
    version_revoked = gateway_app.validate_runtime_revocation_state_for_runtime(
        _record(),
        payload=_payload(),
        revoked_policy_versions={"policy-v1"},
        timestamp=FIXED_TIMESTAMP,
    )

    _assert_fail_closed(runtime_revoked, gateway_app.RUNTIME_DENY_RUNTIME_REVOKED)
    _assert_fail_closed(hash_revoked, gateway_app.RUNTIME_DENY_POLICY_REVOKED)
    _assert_fail_closed(version_revoked, gateway_app.RUNTIME_DENY_POLICY_REVOKED)


def test_runtime_revocation_clear_state_is_next_check_only():
    result = gateway_app.validate_runtime_revocation_state_for_runtime(
        _record(),
        payload=_payload(),
        runtime_state="ACTIVE",
        revoked_policy_hashes=set(),
        revoked_policy_versions=set(),
        timestamp=FIXED_TIMESTAMP,
    )

    _assert_next_check_only(result)
