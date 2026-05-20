from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.deployment_runtime_health import sha256_text
from governance.remote_challenge_response import (
    CHALLENGE_BLOCKED,
    CHALLENGE_DEVICE_MISMATCH,
    CHALLENGE_EXPIRED,
    CHALLENGE_RESPONSE_INVALID,
    CHALLENGE_RESPONSE_VALID,
    CHALLENGE_REPLAY_DETECTED,
    CHALLENGE_SIGNATURE_INVALID,
    signable_challenge_message,
    validate_challenge_response,
)


NOW = "2026-05-20T00:00:00Z"
POLICY_HASH = "a" * 64
DEVICE_FINGERPRINT = sha256_text("device-alpha")
CHALLENGE_ID = "challenge-live-1"
NONCE = "nonce-live-1"


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


def _packet(private_key: Ed25519PrivateKey, **overrides) -> dict:
    packet = {
        "challenge_id": CHALLENGE_ID,
        "nonce": NONCE,
        "issued_at": "2026-05-19T00:00:00Z",
        "expires_at": "2026-05-21T00:00:00Z",
        "device_identity_fingerprint": DEVICE_FINGERPRINT,
        "policy_hash": POLICY_HASH,
        "response_signature_status": "SIGNED",
        "challenge_state": CHALLENGE_RESPONSE_VALID,
    }
    packet.update(overrides)
    packet["signature"] = base64.b64encode(private_key.sign(signable_challenge_message(packet))).decode("ascii")
    return packet


def _validate(packet, public_pem: str, **overrides):
    kwargs = {
        "trusted_public_keys": {DEVICE_FINGERPRINT: public_pem},
        "expected_device_identity_fingerprint": DEVICE_FINGERPRINT,
        "expected_policy_hash": POLICY_HASH,
        "issued_challenges": {CHALLENGE_ID},
        "used_nonces": set(),
        "now_utc": NOW,
    }
    kwargs.update(overrides)
    return validate_challenge_response(packet, **kwargs)


def test_valid_signed_challenge_response_verifies() -> None:
    private_key, public_pem = _keypair()

    result = _validate(_packet(private_key), public_pem)

    assert result.verified is True
    assert result.challenge_state == CHALLENGE_RESPONSE_VALID
    assert result.reason_codes == (CHALLENGE_RESPONSE_VALID,)
    assert result.audit_evidence["policy_hash"] == POLICY_HASH


def test_expired_challenge_blocks() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key, expires_at="2026-05-19T23:59:59Z")

    result = _validate(packet, public_pem)

    assert result.verified is False
    assert result.challenge_state == CHALLENGE_EXPIRED
    assert CHALLENGE_EXPIRED in result.reason_codes
    assert CHALLENGE_BLOCKED in result.reason_codes


def test_replayed_challenge_nonce_blocks() -> None:
    private_key, public_pem = _keypair()

    result = _validate(_packet(private_key), public_pem, used_nonces={NONCE})

    assert result.verified is False
    assert result.challenge_state == CHALLENGE_REPLAY_DETECTED
    assert CHALLENGE_REPLAY_DETECTED in result.reason_codes


def test_invalid_signature_blocks() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key)
    packet["policy_hash"] = "b" * 64

    result = _validate(packet, public_pem)

    assert result.verified is False
    assert result.challenge_state == CHALLENGE_RESPONSE_INVALID
    assert CHALLENGE_SIGNATURE_INVALID in result.reason_codes


def test_wrong_device_fingerprint_blocks() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key, device_identity_fingerprint="b" * 64)

    result = _validate(packet, public_pem)

    assert result.verified is False
    assert CHALLENGE_DEVICE_MISMATCH in result.reason_codes


def test_missing_challenge_blocks() -> None:
    _private_key, public_pem = _keypair()

    result = _validate(None, public_pem)

    assert result.verified is False
    assert result.challenge_state == "CHALLENGE_NOT_ISSUED"
    assert "CHALLENGE_MISSING" in result.reason_codes


def test_challenge_audit_evidence_is_hash_only_and_redacted() -> None:
    private_key, public_pem = _keypair()

    result = _validate(_packet(private_key), public_pem)
    encoded = json.dumps(result.to_dict(), sort_keys=True)

    assert result.audit_evidence["challenge_id_hash"] == sha256_text(CHALLENGE_ID)
    assert result.audit_evidence["nonce_hash"] == sha256_text(NONCE)
    assert CHALLENGE_ID not in encoded
    assert NONCE not in encoded
    assert "device-alpha" not in encoded
    assert "PRIVATE " + "KEY" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "token" not in encoded.lower()
