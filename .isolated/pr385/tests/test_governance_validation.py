from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from memory.governed_memory import GovernedMemory
from runtime.command_model import command_model
import runtime.policy_validator as policy_validator


ROOT = Path(__file__).resolve().parents[1]
DEV_APPROVAL_DIR = ROOT / "approvals" / "dev-ci"


def _point_validator_at_dev_approvals(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy_validator, "APPROVAL_1_JSON", DEV_APPROVAL_DIR / "policy-approval-1.json")
    monkeypatch.setattr(policy_validator, "APPROVAL_1_SIG", DEV_APPROVAL_DIR / "policy-approval-1.sig")
    monkeypatch.setattr(policy_validator, "APPROVAL_1_PUBLIC_KEY", DEV_APPROVAL_DIR / "approver1_public_key.pem")
    monkeypatch.setattr(policy_validator, "APPROVAL_2_JSON", DEV_APPROVAL_DIR / "policy-approval-2.json")
    monkeypatch.setattr(policy_validator, "APPROVAL_2_SIG", DEV_APPROVAL_DIR / "policy-approval-2.sig")
    monkeypatch.setattr(policy_validator, "APPROVAL_2_PUBLIC_KEY", DEV_APPROVAL_DIR / "approver2_public_key.pem")


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
    assert policy_validator.PUBLIC_KEY.exists()
    policy_validator.validate_signature()


def test_committed_policy_artifacts_are_tracked_for_ci_checkout() -> None:
    required = {
        "policy/policy.json",
        "policy/policy.sig",
        "policy/policy.sha256",
        "policy/public_key.pem",
    }

    result = subprocess.run(
        ["git", "ls-files", *sorted(required)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert set(result.stdout.splitlines()) == required


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


def test_dev_approval_artifacts_pass_only_in_dev_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    _point_validator_at_dev_approvals(monkeypatch)
    monkeypatch.setattr(policy_validator, "AUDIT_LOG_JSONL", tmp_path / "audit_log.jsonl")
    monkeypatch.setenv("USBAY_GOVERNANCE_APPROVAL_MODE", "development")
    metadata = policy_validator.load_policy_metadata()

    policy_validator.validate_approval_artifacts(
        policy_hash=metadata["policy_hash"],
        policy_version=metadata["policy_version"],
    )

    monkeypatch.delenv("USBAY_GOVERNANCE_APPROVAL_MODE", raising=False)
    with pytest.raises(RuntimeError, match="POLICY_APPROVAL_DEV_ARTIFACT_FORBIDDEN"):
        policy_validator.validate_approval_artifact(
            label="approval[1]",
            approval_json=DEV_APPROVAL_DIR / "policy-approval-1.json",
            approval_sig=DEV_APPROVAL_DIR / "policy-approval-1.sig",
            approver_public_key=DEV_APPROVAL_DIR / "approver1_public_key.pem",
            policy_hash=metadata["policy_hash"],
            policy_version=metadata["policy_version"],
        )


def test_production_missing_approval_artifacts_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.delenv("USBAY_GOVERNANCE_APPROVAL_MODE", raising=False)
    monkeypatch.setattr(policy_validator, "APPROVAL_1_JSON", tmp_path / "missing-approval.json")
    monkeypatch.setattr(policy_validator, "APPROVAL_1_SIG", tmp_path / "missing-approval.sig")
    monkeypatch.setattr(policy_validator, "APPROVAL_1_PUBLIC_KEY", tmp_path / "missing-approver.pem")
    monkeypatch.setattr(policy_validator, "APPROVAL_2_JSON", tmp_path / "missing-approval-2.json")
    monkeypatch.setattr(policy_validator, "APPROVAL_2_SIG", tmp_path / "missing-approval-2.sig")
    monkeypatch.setattr(policy_validator, "APPROVAL_2_PUBLIC_KEY", tmp_path / "missing-approver-2.pem")
    metadata = policy_validator.load_policy_metadata()

    with pytest.raises(RuntimeError, match="POLICY_APPROVAL_1_MISSING"):
        policy_validator.validate_approval_artifacts(
            policy_hash=metadata["policy_hash"],
            policy_version=metadata["policy_version"],
        )


def test_fake_dev_approval_signature_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("USBAY_GOVERNANCE_APPROVAL_MODE", "development")
    fake_sig = tmp_path / "policy-approval-1.sig"
    fake_sig.write_bytes(b"not-a-valid-signature")
    metadata = policy_validator.load_policy_metadata()

    with pytest.raises(RuntimeError, match="POLICY_APPROVAL_1_SIGNATURE_INVALID"):
        policy_validator.validate_approval_artifact(
            label="approval[1]",
            approval_json=DEV_APPROVAL_DIR / "policy-approval-1.json",
            approval_sig=fake_sig,
            approver_public_key=DEV_APPROVAL_DIR / "approver1_public_key.pem",
            policy_hash=metadata["policy_hash"],
            policy_version=metadata["policy_version"],
        )


def test_dev_approval_artifacts_do_not_include_private_keys_or_tokens() -> None:
    for path in DEV_APPROVAL_DIR.iterdir():
        assert "private" not in path.name.lower()
        assert "token" not in path.name.lower()
        payload = path.read_bytes()
        assert b"PRIVATE KEY" not in payload
        assert b"raw_token" not in payload
        assert b"secret" not in payload.lower()


def test_dev_fixtures_are_isolated_from_production_approval_paths() -> None:
    result = subprocess.run(
        ["git", "ls-files", "approvals"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    tracked = set(result.stdout.splitlines())
    assert result.returncode == 0
    assert "approvals/dev-ci/policy-approval-1.json" in tracked
    assert "approvals/dev-ci/policy-approval-1.sig" in tracked
    assert "approvals/dev-ci/approver1_public_key.pem" in tracked
    assert "approvals/policy-approval-1.json" not in tracked
    assert "approvals/policy-approval-1.sig" not in tracked
    assert "approvals/approver1_public_key.pem" not in tracked
