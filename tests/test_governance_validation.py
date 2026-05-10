from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from memory.governed_memory import GovernedMemory
from runtime.command_model import command_model
import runtime.policy_validator as policy_validator


ROOT = Path(__file__).resolve().parents[1]


def test_governed_memory_requires_device_id() -> None:
    with pytest.raises(TypeError):
        GovernedMemory()


def test_governance_fails_closed_on_invalid_input() -> None:
    with pytest.raises(RuntimeError, match="missing required fields"):
        command_model.validate_command_request_payload({})


def test_command_model_delegates_to_policy_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    def mismatch_validator(_payload):
        raise RuntimeError("validator_mismatch")

    monkeypatch.setattr(policy_validator, "validate_command_request_payload", mismatch_validator)

    with pytest.raises(RuntimeError, match="validator_mismatch"):
        command_model.validate_command_request_payload(
            {"input": "test", "actor_id": "actor", "purpose": "validation"}
        )


def test_policy_validation_rejects_invalid_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path
) -> None:
    invalid_policy = tmp_path / "policy.json"
    invalid_policy.write_text('{"policy_version": ', encoding="utf-8")

    monkeypatch.setattr(policy_validator, "POLICY_JSON", invalid_policy)

    with pytest.raises(ValueError, match="invalid JSON"):
        policy_validator.validate_policy_json()


def test_policy_sha256_validation_accepts_matching_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path
) -> None:
    policy = tmp_path / "policy.json"
    expected = tmp_path / "policy.sha256"
    policy.write_text('{"policy_version":"test","rules":[]}\n', encoding="utf-8")
    expected.write_text(hashlib.sha256(policy.read_bytes()).hexdigest() + "\n", encoding="utf-8")

    monkeypatch.setattr(policy_validator, "POLICY_JSON", policy)
    monkeypatch.setattr(policy_validator, "POLICY_SHA256", expected)

    policy_validator.validate_sha256()


def test_policy_sha256_validation_fails_closed_on_changed_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path
) -> None:
    policy = tmp_path / "policy.json"
    expected = tmp_path / "policy.sha256"
    policy.write_text('{"policy_version":"test","rules":[]}\n', encoding="utf-8")
    expected.write_text(hashlib.sha256(policy.read_bytes()).hexdigest() + "\n", encoding="utf-8")
    policy.write_text('{"policy_version":"changed","rules":[]}\n', encoding="utf-8")

    monkeypatch.setattr(policy_validator, "POLICY_JSON", policy)
    monkeypatch.setattr(policy_validator, "POLICY_SHA256", expected)

    with pytest.raises(ValueError, match="sha256 mismatch"):
        policy_validator.validate_sha256()


def test_committed_policy_sha256_matches_policy_document() -> None:
    policy = ROOT / "policy" / "policy.json"
    expected = (ROOT / "policy" / "policy.sha256").read_text(encoding="utf-8").split()[0]

    assert hashlib.sha256(policy.read_bytes()).hexdigest() == expected


def test_committed_policy_signature_artifact_is_not_hex_placeholder() -> None:
    signature = (ROOT / "policy" / "policy.sig").read_bytes()

    assert len(signature) in {64, 256}
    assert not all(byte in b"0123456789abcdefABCDEF\r\n" for byte in signature)


def test_committed_policy_signature_verifies_when_public_key_is_present() -> None:
    if not policy_validator.PUBLIC_KEY.exists():
        pytest.skip("policy public key is secret-provisioned in CI")

    policy_validator.validate_signature()


def test_policy_signature_validation_fails_closed_on_changed_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    policy = tmp_path / "policy.json"
    signature = tmp_path / "policy.sig"
    public_key = tmp_path / "public_key.pem"
    private_key = Ed25519PrivateKey.generate()

    policy.write_text('{"policy_version":"signed","rules":[]}\n', encoding="utf-8")
    signature.write_bytes(private_key.sign(policy.read_bytes()))
    public_key.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    monkeypatch.setattr(policy_validator, "POLICY_JSON", policy)
    monkeypatch.setattr(policy_validator, "POLICY_SIG", signature)
    monkeypatch.setattr(policy_validator, "PUBLIC_KEY", public_key)

    policy_validator.validate_signature()

    policy.write_text('{"policy_version":"changed","rules":[]}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="signature verification failed"):
        policy_validator.validate_signature()
