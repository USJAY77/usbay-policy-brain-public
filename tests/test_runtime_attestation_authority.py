from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.deployment_runtime_health import deployment_runtime_health
from governance.runtime_attestation_authority import (
    RUNTIME_ATTESTATION_BLOCKED,
    RUNTIME_ATTESTATION_INVALID,
    RUNTIME_ATTESTATION_MISSING,
    RUNTIME_ATTESTATION_POLICY_MISMATCH,
    RUNTIME_ATTESTATION_SIGNED,
    attestation_hash,
    create_signed_runtime_attestation,
    missing_runtime_attestation,
    public_key_from_private_key,
    verify_runtime_attestation,
)


ROOT = Path(__file__).resolve().parents[1]


def _keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _runtime_snapshot(**overrides) -> dict:
    snapshot = {
        "status": "OK",
        "mode": "NORMAL",
        "policy_signature_valid": True,
        "policy_version": "policy-v1",
        "policy_hash": "a" * 64,
        "replay_protection_active": True,
        "runtime_parity": {"runtime_parity_status": "VERIFIED"},
    }
    snapshot.update(overrides)
    return snapshot


def _deployment_health() -> dict:
    return deployment_runtime_health(
        root=ROOT,
        runtime_snapshot=_runtime_snapshot(),
        audit_chain_entries=[],
    )


def test_signed_runtime_attestation_verifies() -> None:
    private_key, public_key = _keypair()

    attestation = create_signed_runtime_attestation(
        root=ROOT,
        deployment_health=_deployment_health(),
        runtime_snapshot=_runtime_snapshot(),
        audit_chain_entries=[],
        audit_chain_valid=True,
        private_key_pem=private_key,
        public_key_pem=public_key,
        deployment_timestamp_utc="2026-05-20T00:00:00Z",
    )
    verification = verify_runtime_attestation(attestation, public_key, expected_policy_hash="a" * 64)

    assert attestation["attestation_status"] == "SIGNED"
    assert attestation["signature_valid"] is True
    assert RUNTIME_ATTESTATION_SIGNED in attestation["reason_codes"]
    assert verification.valid is True
    assert verification.status == "VERIFIED"


def test_attestation_binds_deployment_health_and_audit_chain() -> None:
    private_key, public_key = _keypair()
    health = _deployment_health()

    attestation = create_signed_runtime_attestation(
        root=ROOT,
        deployment_health=health,
        runtime_snapshot=_runtime_snapshot(),
        audit_chain_entries=[{"hash_current": "b" * 64}],
        audit_chain_valid=True,
        private_key_pem=private_key,
        public_key_pem=public_key,
        deployment_timestamp_utc="2026-05-20T00:00:00Z",
    )

    assert attestation["deployment_health_hash"] == health["health_evidence_hash"]
    assert attestation["audit_chain_status"] == "VERIFIED"
    assert attestation["audit_chain_hash"]
    assert attestation["startup_command_hash"]


def test_tampered_attestation_fails_closed() -> None:
    private_key, public_key = _keypair()
    attestation = create_signed_runtime_attestation(
        root=ROOT,
        deployment_health=_deployment_health(),
        runtime_snapshot=_runtime_snapshot(),
        audit_chain_entries=[],
        audit_chain_valid=True,
        private_key_pem=private_key,
        public_key_pem=public_key,
        deployment_timestamp_utc="2026-05-20T00:00:00Z",
    )
    tampered = dict(attestation)
    tampered["policy_hash"] = "b" * 64

    verification = verify_runtime_attestation(tampered, public_key, expected_policy_hash="a" * 64)

    assert verification.valid is False
    assert RUNTIME_ATTESTATION_INVALID in verification.reason_codes
    assert RUNTIME_ATTESTATION_POLICY_MISMATCH in verification.reason_codes


def test_missing_runtime_attestation_is_blocked() -> None:
    missing = missing_runtime_attestation()

    assert missing["attestation_status"] == "BLOCKED"
    assert missing["signature_valid"] is False
    assert RUNTIME_ATTESTATION_MISSING in missing["reason_codes"]
    assert RUNTIME_ATTESTATION_BLOCKED in missing["reason_codes"]


def test_wrong_public_key_fails_closed() -> None:
    private_key, _public_key = _keypair()
    _wrong_private, wrong_public = _keypair()
    attestation = create_signed_runtime_attestation(
        root=ROOT,
        deployment_health=_deployment_health(),
        runtime_snapshot=_runtime_snapshot(),
        audit_chain_entries=[],
        audit_chain_valid=True,
        private_key_pem=private_key,
        public_key_pem=public_key_from_private_key(private_key),
        deployment_timestamp_utc="2026-05-20T00:00:00Z",
    )

    verification = verify_runtime_attestation(attestation, wrong_public)

    assert verification.valid is False
    assert RUNTIME_ATTESTATION_INVALID in verification.reason_codes


def test_blocked_deployment_health_signs_blocked_attestation() -> None:
    private_key, public_key = _keypair()

    attestation = create_signed_runtime_attestation(
        root=ROOT,
        deployment_health={**_deployment_health(), "status": "BLOCKED"},
        runtime_snapshot=_runtime_snapshot(),
        audit_chain_entries=[],
        audit_chain_valid=True,
        private_key_pem=private_key,
        public_key_pem=public_key,
        deployment_timestamp_utc="2026-05-20T00:00:00Z",
    )

    assert attestation["attestation_status"] == "BLOCKED"
    assert RUNTIME_ATTESTATION_BLOCKED in attestation["reason_codes"]


def test_runtime_attestation_output_is_hash_only_and_redacted() -> None:
    private_key, public_key = _keypair()

    attestation = create_signed_runtime_attestation(
        root=ROOT,
        deployment_health=_deployment_health(),
        runtime_snapshot=_runtime_snapshot(),
        audit_chain_entries=[],
        audit_chain_valid=True,
        private_key_pem=private_key,
        public_key_pem=public_key,
        deployment_timestamp_utc="2026-05-20T00:00:00Z",
    )
    encoded = json.dumps(attestation, sort_keys=True)

    assert attestation_hash(attestation)
    assert public_key not in encoded
    assert "PRIVATE " + "KEY" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "token" not in encoded.lower()
