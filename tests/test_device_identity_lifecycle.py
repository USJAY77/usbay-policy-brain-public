from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.deployment_runtime_health import canonical_json, sha256_text
from governance.device_identity_lifecycle import (
    IDENTITY_BLOCKED,
    IDENTITY_CHALLENGE_STALE,
    IDENTITY_EXPIRED,
    IDENTITY_REVOKED,
    IDENTITY_SIGNATURE_INVALID,
    IDENTITY_VALIDATION_PASSED,
    IDENTITY_VERIFIED,
    public_key_fingerprint,
    signable_identity_message,
    validate_identity_packet,
)


NOW = "2026-05-20T00:00:00Z"
POLICY_VERSION = "policy-v1"
POLICY_HASH = "a" * 64
CHALLENGE_ID = "challenge-2026-05-20"
NONCE = "nonce-2026-05-20"


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


def _packet(private_key: Ed25519PrivateKey, public_pem: str, **overrides) -> dict:
    packet = {
        "device_id_fingerprint": sha256_text("device-alpha"),
        "policy_version": POLICY_VERSION,
        "issued_at": "2026-05-19T00:00:00Z",
        "expires_at": "2026-05-21T00:00:00Z",
        "nonce": NONCE,
        "challenge_id": CHALLENGE_ID,
        "public_key_fingerprint": public_key_fingerprint(public_pem),
        "signature_status": "SIGNED",
        "identity_state": IDENTITY_VERIFIED,
    }
    packet.update(overrides)
    packet["signature"] = base64.b64encode(private_key.sign(signable_identity_message(packet))).decode("ascii")
    return packet


def _validate(packet: dict, public_pem: str, **overrides):
    kwargs = {
        "trusted_public_keys": {public_key_fingerprint(public_pem): public_pem},
        "expected_policy_version": POLICY_VERSION,
        "expected_policy_hash": POLICY_HASH,
        "active_challenges": {CHALLENGE_ID},
        "used_nonces": set(),
        "now_utc": NOW,
    }
    kwargs.update(overrides)
    return validate_identity_packet(packet, **kwargs)


def test_valid_identity_verifies() -> None:
    private_key, public_pem = _keypair()
    result = _validate(_packet(private_key, public_pem), public_pem)

    assert result.verified is True
    assert result.identity_state == IDENTITY_VERIFIED
    assert result.reason_codes == (IDENTITY_VALIDATION_PASSED,)
    assert result.audit_evidence["policy_hash"] == POLICY_HASH
    assert result.audit_evidence["public_key_fingerprint"] == public_key_fingerprint(public_pem)


def test_expired_identity_blocks() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key, public_pem, expires_at="2026-05-19T23:59:59Z")

    result = _validate(packet, public_pem)

    assert result.verified is False
    assert result.identity_state == IDENTITY_EXPIRED
    assert IDENTITY_EXPIRED in result.reason_codes
    assert IDENTITY_BLOCKED in result.reason_codes


def test_revoked_identity_blocks() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key, public_pem)

    result = _validate(
        packet,
        public_pem,
        revoked_public_key_fingerprints={public_key_fingerprint(public_pem)},
    )

    assert result.verified is False
    assert result.identity_state == IDENTITY_REVOKED
    assert IDENTITY_REVOKED in result.reason_codes


def test_invalid_signature_blocks() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key, public_pem)
    packet["policy_version"] = "policy-v2"

    result = _validate(packet, public_pem)

    assert result.verified is False
    assert result.identity_state == IDENTITY_SIGNATURE_INVALID
    assert IDENTITY_SIGNATURE_INVALID in result.reason_codes


def test_stale_nonce_and_challenge_block() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key, public_pem)

    result = _validate(packet, public_pem, active_challenges=set(), used_nonces={NONCE})

    assert result.verified is False
    assert "IDENTITY_NONCE_STALE" in result.reason_codes
    assert IDENTITY_CHALLENGE_STALE in result.reason_codes


def test_policy_mismatch_blocks() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key, public_pem)

    result = _validate(packet, public_pem, expected_policy_version="policy-v2")

    assert result.verified is False
    assert "IDENTITY_POLICY_MISMATCH" in result.reason_codes


def test_missing_identity_blocks() -> None:
    result = validate_identity_packet(
        None,
        trusted_public_keys={},
        expected_policy_version=POLICY_VERSION,
        expected_policy_hash=POLICY_HASH,
        now_utc=NOW,
    )

    assert result.verified is False
    assert result.identity_state == "IDENTITY_UNENROLLED"
    assert "IDENTITY_MISSING" in result.reason_codes


def test_identity_audit_evidence_is_hash_only_and_redacted() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key, public_pem)

    result = _validate(packet, public_pem)
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


def test_raw_device_identifier_field_fails_closed() -> None:
    private_key, public_pem = _keypair()
    packet = _packet(private_key, public_pem)
    packet["device_id"] = "device-alpha"
    packet["signature"] = base64.b64encode(private_key.sign(signable_identity_message(packet))).decode("ascii")

    result = _validate(packet, public_pem)

    assert result.verified is False
    assert result.identity_state == IDENTITY_SIGNATURE_INVALID
    assert "IDENTITY_PACKET_MALFORMED" in result.reason_codes
