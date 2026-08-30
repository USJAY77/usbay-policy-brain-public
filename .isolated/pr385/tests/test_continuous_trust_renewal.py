from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.continuous_trust_renewal import (
    TRUST_RENEWAL_ACTIVE,
    TRUST_RENEWAL_BLOCKED,
    TRUST_RENEWAL_CHALLENGE_CHAIN_STALE,
    TRUST_RENEWAL_EXPIRED,
    TRUST_RENEWAL_REPLAY_BLOCKED,
    TRUST_RENEWAL_SIGNATURE_INVALID,
    signable_renewal_message,
    validate_trust_renewal,
)
from governance.deployment_runtime_health import sha256_text


NOW = "2026-05-20T00:00:00Z"
POLICY_HASH = "a" * 64
DEVICE_FINGERPRINT = sha256_text("device-alpha")
PREVIOUS_CHALLENGE_HASH = "b" * 64
RENEWAL_ID = "renewal-1"
NEW_CHALLENGE_ID = "challenge-next-1"
NONCE_HASH = sha256_text("renewal-nonce-1")


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


def _packet(private_key: Ed25519PrivateKey, **overrides) -> dict:
    packet = {
        "renewal_id": RENEWAL_ID,
        "previous_challenge_hash": PREVIOUS_CHALLENGE_HASH,
        "new_challenge_id": NEW_CHALLENGE_ID,
        "nonce_hash": NONCE_HASH,
        "device_identity_fingerprint": DEVICE_FINGERPRINT,
        "policy_hash": POLICY_HASH,
        "issued_at": "2026-05-20T00:00:00Z",
        "expires_at": "2026-05-20T00:05:00Z",
        "renewal_window_seconds": "300",
        "signature_status": "SIGNED",
        "renewal_state": TRUST_RENEWAL_ACTIVE,
    }
    packet.update(overrides)
    packet["signature"] = base64.b64encode(private_key.sign(signable_renewal_message(packet))).decode("ascii")
    return packet


def _validate(packet, public_pem: str, **overrides):
    kwargs = {
        "trusted_public_keys": {DEVICE_FINGERPRINT: public_pem},
        "expected_device_identity_fingerprint": DEVICE_FINGERPRINT,
        "expected_policy_hash": POLICY_HASH,
        "expected_previous_challenge_hash": PREVIOUS_CHALLENGE_HASH,
        "used_nonce_hashes": set(),
        "now_utc": NOW,
    }
    kwargs.update(overrides)
    return validate_trust_renewal(packet, **kwargs)


def test_valid_trust_renewal_verifies() -> None:
    private_key, public_pem = _keypair()

    result = _validate(_packet(private_key), public_pem)

    assert result.verified is True
    assert result.renewal_state == TRUST_RENEWAL_ACTIVE
    assert result.reason_codes == (TRUST_RENEWAL_ACTIVE,)
    assert result.audit_evidence["policy_hash"] == POLICY_HASH
    assert result.audit_evidence["previous_challenge_hash"] == PREVIOUS_CHALLENGE_HASH


def test_expired_renewal_blocks() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key, expires_at="2026-05-19T23:59:59Z")

    result = _validate(packet, public_pem)

    assert result.verified is False
    assert result.renewal_state == TRUST_RENEWAL_EXPIRED
    assert TRUST_RENEWAL_EXPIRED in result.reason_codes
    assert TRUST_RENEWAL_BLOCKED in result.reason_codes


def test_replayed_renewal_nonce_blocks() -> None:
    private_key, public_pem = _keypair()

    result = _validate(_packet(private_key), public_pem, used_nonce_hashes={NONCE_HASH})

    assert result.verified is False
    assert result.renewal_state == TRUST_RENEWAL_REPLAY_BLOCKED
    assert TRUST_RENEWAL_REPLAY_BLOCKED in result.reason_codes


def test_invalid_signature_blocks() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key)
    packet["policy_hash"] = "c" * 64

    result = _validate(packet, public_pem)

    assert result.verified is False
    assert TRUST_RENEWAL_SIGNATURE_INVALID in result.reason_codes


def test_stale_challenge_chain_blocks() -> None:
    private_key, public_pem = _keypair()

    result = _validate(_packet(private_key), public_pem, expected_previous_challenge_hash="c" * 64)

    assert result.verified is False
    assert TRUST_RENEWAL_CHALLENGE_CHAIN_STALE in result.reason_codes


def test_missing_renewal_blocks() -> None:
    _private_key, public_pem = _keypair()

    result = _validate(None, public_pem)

    assert result.verified is False
    assert result.renewal_state == "TRUST_RENEWAL_NOT_STARTED"
    assert "TRUST_RENEWAL_MISSING" in result.reason_codes


def test_renewal_audit_evidence_is_hash_only_and_redacted() -> None:
    private_key, public_pem = _keypair()

    result = _validate(_packet(private_key), public_pem)
    encoded = json.dumps(result.to_dict(), sort_keys=True)

    assert result.audit_evidence["renewal_id_hash"] == sha256_text(RENEWAL_ID)
    assert result.audit_evidence["new_challenge_hash"] == sha256_text(NEW_CHALLENGE_ID)
    assert result.audit_evidence["nonce_hash"] == NONCE_HASH
    assert RENEWAL_ID not in encoded
    assert NEW_CHALLENGE_ID not in encoded
    assert "renewal-nonce-1" not in encoded
    assert "device-alpha" not in encoded
    assert "PRIVATE " + "KEY" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "token" not in encoded.lower()
