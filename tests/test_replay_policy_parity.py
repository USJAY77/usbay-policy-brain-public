"""Synthetic Gateway/attested-producer replay configuration parity."""
import hashlib
import json

import pytest

import gateway.app as gateway
from security import confidential_space_attestation as cs
from security.decision_store import DecisionStoreError
from security.replay_policy import ReplayPolicyError, load_replay_policy
from security.request_signing import request_signature_message
from tests.test_confidential_space_attestation import fixture

pytestmark = [pytest.mark.governance, pytest.mark.regression]
ENV_NAMES = (
    "USBAY_REPLAY_POLICY_PATH", "USBAY_NONCE_TTL_SECONDS",
    "USBAY_TIMESTAMP_SKEW_SECONDS", "USBAY_MAX_CLOCK_SKEW_SECONDS",
    "USBAY_REPLAY_FAIL_CLOSED",
)


@pytest.mark.parametrize("policy,env,ttl,skew", [
    (None, {}, 300, 30),
    ({}, {}, 300, 30),
    ({"nonce_ttl_seconds": 600, "timestamp_skew_seconds": 60}, {}, 600, 60),
    ({"max_request_age_seconds": 700, "max_clock_skew_seconds": 70}, {}, 700, 70),
    ({"nonce_ttl_seconds": 600, "max_request_age_seconds": 700,
      "timestamp_skew_seconds": 60, "max_clock_skew_seconds": 70}, {}, 600, 60),
    ({}, {"USBAY_NONCE_TTL_SECONDS": "900", "USBAY_TIMESTAMP_SKEW_SECONDS": "90"}, 900, 90),
    ({}, {"USBAY_MAX_CLOCK_SKEW_SECONDS": "80"}, 300, 80),
    ({}, {"USBAY_TIMESTAMP_SKEW_SECONDS": "90", "USBAY_MAX_CLOCK_SKEW_SECONDS": "80"}, 300, 90),
])
def test_replay_policy_normalization_parity(tmp_path, monkeypatch, policy, env, ttl, skew):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / "custom-replay.json"
    if policy is not None:
        path.write_text(json.dumps(policy))
    monkeypatch.setenv("USBAY_REPLAY_POLICY_PATH", str(path))
    # Preserve Gateway's existing import-time path configuration API.
    monkeypatch.setattr(gateway, "REPLAY_POLICY_PATH", path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    expected = dict(nonce_ttl_seconds=ttl, timestamp_skew_seconds=skew, replay_fail_closed=True)
    assert gateway.replay_policy_config() == load_replay_policy() == expected


@pytest.mark.parametrize("raw,env,reason", [
    ("{", {}, "json"),
    ("[]", {}, "root"),
    ('{"nonce_ttl_seconds":0}', {}, "nonce_ttl_seconds"),
    ('{"timestamp_skew_seconds":-1}', {}, "timestamp_skew_seconds"),
    ('{"replay_fail_closed":false}', {}, "replay_fail_closed"),
    ("{}", {"USBAY_NONCE_TTL_SECONDS": "invalid"}, "nonce_ttl_seconds"),
    ("{}", {"USBAY_REPLAY_FAIL_CLOSED": "false"}, "replay_fail_closed"),
])
def test_replay_policy_errors_remain_fail_closed(tmp_path, monkeypatch, raw, env, reason):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / "invalid.json"
    path.write_text(raw)
    monkeypatch.setenv("USBAY_REPLAY_POLICY_PATH", str(path))
    monkeypatch.setattr(gateway, "REPLAY_POLICY_PATH", path)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ReplayPolicyError, match="invalid_replay_policy:" + reason):
        load_replay_policy()
    with pytest.raises(DecisionStoreError, match="invalid_replay_policy:" + reason):
        gateway.replay_policy_config()


@pytest.mark.parametrize("mode", ["custom_path", "environment", "legacy_file", "legacy_environment"])
def test_authenticated_producer_matches_gateway_nondefault_window(fixture, monkeypatch, mode):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    path = fixture["tmp"] / "custom-replay.json"
    policy = {"nonce_ttl_seconds": 600, "timestamp_skew_seconds": 90}
    offset = -450
    if mode == "legacy_file":
        policy = {"max_request_age_seconds": 600, "max_clock_skew_seconds": 90}
    elif mode == "environment":
        policy = {}
        monkeypatch.setenv("USBAY_NONCE_TTL_SECONDS", "600")
        monkeypatch.setenv("USBAY_TIMESTAMP_SKEW_SECONDS", "90")
    elif mode == "legacy_environment":
        policy = {}
        offset = 60
        monkeypatch.setenv("USBAY_MAX_CLOCK_SKEW_SECONDS", "90")
    path.write_text(json.dumps(policy))
    monkeypatch.setenv("USBAY_REPLAY_POLICY_PATH", str(path))
    monkeypatch.setattr(gateway, "REPLAY_POLICY_PATH", path)
    node, _, version, context = fixture["request"]()
    original = context["confidential_space_signed_request"]
    unsigned = {k: v for k, v in original.items() if k not in {"signature", "signature_alg", "pubkey_id"}}
    unsigned["timestamp"] += offset
    # Signing with the fixture key is required; changing an authenticated timestamp
    # without signing it would exercise a different rejection boundary.
    signed = fixture["sign_request"](unsigned)
    context["confidential_space_signed_request"] = signed
    rh = hashlib.sha256(request_signature_message(signed).encode()).hexdigest()
    assert gateway.validate_request_timestamp(signed)[:2] == (True, "ok")
    config, attestation_policy = cs.settings()
    calls = []
    def acquire(audience, nonce):
        calls.append(nonce)
        return fixture["sign"](fixture["claims"](nonce))
    packet = cs.produce(node, rh, version, context, config, attestation_policy, acquire=acquire)
    expected = cs.scope(node, rh, version, context)
    assert len(calls) == 1
    decision = cs.verify(packet, expected, config, attestation_policy)
    assert decision.request_hash == rh and decision.decision == "allow"
    with pytest.raises(cs.AttestationRejected, match="REPLAY"):
        cs.verify(packet, expected, config, attestation_policy)


@pytest.mark.parametrize("mode", ["malformed", "fail_open", "expired"])
def test_producer_rejects_before_acquisition(fixture, monkeypatch, mode):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    path = fixture["tmp"] / "reject-replay.json"
    path.write_text("{" if mode == "malformed" else json.dumps(
        {"replay_fail_closed": False} if mode == "fail_open" else {"nonce_ttl_seconds": 1}))
    monkeypatch.setenv("USBAY_REPLAY_POLICY_PATH", str(path))
    monkeypatch.setattr(gateway, "REPLAY_POLICY_PATH", path)
    node, _, version, context = fixture["request"]()
    signed = context["confidential_space_signed_request"]
    unsigned = {k: v for k, v in signed.items() if k not in {"signature", "signature_alg", "pubkey_id"}}
    unsigned["timestamp"] -= 10
    signed = fixture["sign_request"](unsigned)
    context["confidential_space_signed_request"] = signed
    rh = hashlib.sha256(request_signature_message(signed).encode()).hexdigest()
    assert gateway.validate_request_timestamp(signed)[0] is False
    config, policy = cs.settings()
    calls = []
    with pytest.raises(cs.AttestationRejected, match="REQUEST_FRESHNESS"):
        cs.produce(node, rh, version, context, config, policy, acquire=lambda *args: calls.append(args))
    assert calls == []
