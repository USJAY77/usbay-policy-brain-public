from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
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


def _sha_ref(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _write_rsa_public_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _sign_bytes(private_key: rsa.RSAPrivateKey, payload: bytes) -> bytes:
    return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


def _write_registry_signature(path: Path, registry_path: Path, private_key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(_sign_bytes(private_key, registry_path.read_bytes()))


def _write_policy_authority_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    approval_mutation=None,
    registry_mutation=None,
    tamper_registry_after_signing: bool = False,
    tamper_approval_after_signing: bool = False,
    same_approver: bool = False,
    same_key: bool = False,
    invalid_registry_signature: bool = False,
) -> dict[str, Path]:
    monkeypatch.delenv("USBAY_GOVERNANCE_APPROVAL_MODE", raising=False)
    monkeypatch.setattr(policy_validator, "AUDIT_LOG_JSONL", tmp_path / "audit_log.jsonl")
    policy_sha_path = tmp_path / "policy.sha256"
    policy_sha_path.write_text(policy_validator.compute_policy_hash() + "\n", encoding="utf-8")
    monkeypatch.setattr(policy_validator, "POLICY_SHA256", policy_sha_path)

    registry_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    approver_1_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    approver_2_key = approver_1_key if same_key else rsa.generate_private_key(public_exponent=65537, key_size=2048)

    paths = {
        "approval_1_json": tmp_path / "policy-approval-1.json",
        "approval_1_sig": tmp_path / "policy-approval-1.sig",
        "approval_1_public": tmp_path / "approver1_public_key.pem",
        "approval_2_json": tmp_path / "policy-approval-2.json",
        "approval_2_sig": tmp_path / "policy-approval-2.sig",
        "approval_2_public": tmp_path / "approver2_public_key.pem",
        "registry_json": tmp_path / "policy_authority_approvers.json",
        "registry_sig": tmp_path / "policy_authority_approvers.sig",
        "registry_public": tmp_path / "policy_authority_registry_public_key.pem",
    }
    monkeypatch.setattr(policy_validator, "APPROVAL_1_JSON", paths["approval_1_json"])
    monkeypatch.setattr(policy_validator, "APPROVAL_1_SIG", paths["approval_1_sig"])
    monkeypatch.setattr(policy_validator, "APPROVAL_1_PUBLIC_KEY", paths["approval_1_public"])
    monkeypatch.setattr(policy_validator, "APPROVAL_2_JSON", paths["approval_2_json"])
    monkeypatch.setattr(policy_validator, "APPROVAL_2_SIG", paths["approval_2_sig"])
    monkeypatch.setattr(policy_validator, "APPROVAL_2_PUBLIC_KEY", paths["approval_2_public"])
    monkeypatch.setattr(policy_validator, "APPROVER_REGISTRY_JSON", paths["registry_json"])
    monkeypatch.setattr(policy_validator, "APPROVER_REGISTRY_SIG", paths["registry_sig"])
    monkeypatch.setattr(policy_validator, "APPROVER_REGISTRY_PUBLIC_KEY", paths["registry_public"])

    _write_rsa_public_key(paths["approval_1_public"], approver_1_key)
    _write_rsa_public_key(paths["approval_2_public"], approver_2_key)
    _write_rsa_public_key(paths["registry_public"], registry_key)

    policy_hash = policy_validator.compute_policy_hash()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    timestamp = now.isoformat().replace("+00:00", "Z")
    approval_1 = {
        "approval_scope": "PRODUCTION",
        "approved_at": timestamp,
        "approver": "USBAY Governance Approver 1",
        "approver_id": "human-approver-1",
        "approver_type": "human",
        "author": "USBAY Governance Authority",
        "environment": "production",
        "nonce": "policy-authority-nonce-1",
        "policy_hash": policy_hash,
        "policy_version": "1.0",
        "reason": "Synthetic test approval for validator enforcement only.",
        "status": "approved",
        "timestamp": timestamp,
    }
    approval_2 = {**approval_1, "approver": "USBAY Governance Approver 2", "approver_id": "human-approver-2", "nonce": "policy-authority-nonce-2"}
    if same_approver:
        approval_2["approver_id"] = approval_1["approver_id"]
    approvals = [approval_1, approval_2]
    if approval_mutation:
        approval_mutation(approvals)

    for approval, json_path, sig_path, key in (
        (approval_1, paths["approval_1_json"], paths["approval_1_sig"], approver_1_key),
        (approval_2, paths["approval_2_json"], paths["approval_2_sig"], approver_2_key),
    ):
        json_path.write_bytes(policy_validator._canonical_json_bytes(approval))
        sig_path.write_bytes(_sign_bytes(key, policy_validator._approval_signature_payload(approval)))
    if tamper_approval_after_signing:
        approval_1["reason"] = "tampered after signing"
        paths["approval_1_json"].write_bytes(policy_validator._canonical_json_bytes(approval_1))

    fingerprint_1 = policy_validator._public_key_fingerprint(paths["approval_1_public"])
    fingerprint_2 = policy_validator._public_key_fingerprint(paths["approval_2_public"])
    registry = {
        "schema": "usbay.policy_authority_approvers.v1",
        "owner": "USBAY Governance Authority",
        "registry_version": "2026.09.test",
        "authority_scope": "ai_act_live_policy_engine",
        "authorized_environments": ["production"],
        "fail_closed": True,
        "valid_from": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "valid_until": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "approvers": [
            {
                "approver_id": "human-approver-1",
                "human_identity_reference": _sha_ref("human-approver-1"),
                "authority_type": "human",
                "public_key_fingerprint": fingerprint_1,
                "authorized_scope": ["ai_act_live_policy_engine"],
                "authorized_environment": ["production"],
                "valid_from": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "valid_until": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
                "revoked": False,
            },
            {
                "approver_id": "human-approver-2",
                "human_identity_reference": _sha_ref("human-approver-2"),
                "authority_type": "human",
                "public_key_fingerprint": fingerprint_2,
                "authorized_scope": ["ai_act_live_policy_engine"],
                "authorized_environment": ["production"],
                "valid_from": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "valid_until": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
                "revoked": False,
            },
        ],
        "revocation_state": {
            "status": "CURRENT",
            "checked_at": timestamp,
            "freshness_seconds": 300,
            "evidence_hash": _sha_ref("revocation-state"),
        },
        "replay_registry": {
            "status": "CURRENT",
            "durable": True,
            "shared_across_instances": True,
            "evidence_hash": _sha_ref("replay-registry"),
            "consumed_nonce_hashes": [],
        },
    }
    if registry_mutation:
        registry_mutation(registry, approvals)
    paths["registry_json"].write_bytes(policy_validator._canonical_json_bytes(registry))
    signing_key = approver_1_key if invalid_registry_signature else registry_key
    _write_registry_signature(paths["registry_sig"], paths["registry_json"], signing_key)
    if tamper_registry_after_signing:
        registry["registry_version"] = "tampered"
        paths["registry_json"].write_bytes(policy_validator._canonical_json_bytes(registry))
    return paths


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


def test_production_policy_authority_registry_with_two_human_approvals_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _write_policy_authority_fixture(monkeypatch, tmp_path)
    metadata = policy_validator.load_policy_metadata()

    result = policy_validator.validate_approval_artifacts(
        policy_hash=metadata["policy_hash"],
        policy_version=metadata["policy_version"],
    )
    second_result = policy_validator.validate_approval_artifacts(
        policy_hash=metadata["policy_hash"],
        policy_version=metadata["policy_version"],
    )

    assert result == second_result
    assert result["authority_validation_reference"].startswith("sha256:")
    assert result["approver_registry_hash"].startswith("sha256:")


def test_policy_authority_registry_schema_is_public_metadata_only() -> None:
    schema_path = ROOT / "approvals" / "policy_authority_approvers.schema.json"
    payload = json.loads(schema_path.read_text(encoding="utf-8"))
    serialized = json.dumps(payload).lower()

    assert payload["properties"]["schema"]["const"] == "usbay.policy_authority_approvers.v1"
    assert payload["properties"]["owner"]["const"] == "USBAY Governance Authority"
    assert "private key" not in serialized
    assert "token" not in serialized
    assert "secret" not in serialized


def test_dev_approval_artifacts_return_development_only_authority_reference(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _point_validator_at_dev_approvals(monkeypatch)
    monkeypatch.setattr(policy_validator, "AUDIT_LOG_JSONL", tmp_path / "audit_log.jsonl")
    monkeypatch.setenv("USBAY_GOVERNANCE_APPROVAL_MODE", "development")
    metadata = policy_validator.load_policy_metadata()

    result = policy_validator.validate_approval_artifacts(
        policy_hash=metadata["policy_hash"],
        policy_version=metadata["policy_version"],
    )

    assert result["authority_validation_reference"].startswith("sha256:")


@pytest.mark.parametrize(
    ("name", "kwargs", "expected"),
    [
        (
            "malformed_registry",
            {"registry_mutation": lambda registry, approvals: registry.update(schema="wrong")},
            "POLICY_AUTHORITY_APPROVER_REGISTRY_MALFORMED",
        ),
        (
            "invalid_registry_signature",
            {"invalid_registry_signature": True},
            "POLICY_AUTHORITY_APPROVER_REGISTRY_SIGNATURE_INVALID",
        ),
        (
            "unauthorized_approver_scope",
            {"registry_mutation": lambda registry, approvals: registry["approvers"][0].update(authorized_scope=["other"])},
            "POLICY_APPROVAL_SCOPE_UNAUTHORIZED",
        ),
        (
            "unknown_approver",
            {"approval_mutation": lambda approvals: approvals[0].update(approver_id="unknown-human")},
            "POLICY_APPROVAL_UNAUTHORIZED_APPROVER",
        ),
        (
            "non_human_registered_approver",
            {"registry_mutation": lambda registry, approvals: registry["approvers"][0].update(authority_type="service")},
            "POLICY_AUTHORITY_APPROVER_NOT_HUMAN",
        ),
        (
            "ai_approval_attempt",
            {"approval_mutation": lambda approvals: approvals[0].update(approver_type="ai")},
            "POLICY_APPROVAL_AI_AUTHORITY_FORBIDDEN",
        ),
        (
            "model_approval_attempt",
            {"approval_mutation": lambda approvals: approvals[0].update(approver_type="model")},
            "POLICY_APPROVAL_AI_AUTHORITY_FORBIDDEN",
        ),
        (
            "provider_approval_attempt",
            {"approval_mutation": lambda approvals: approvals[0].update(approver_type="provider")},
            "POLICY_APPROVAL_AI_AUTHORITY_FORBIDDEN",
        ),
        (
            "wrong_environment",
            {"approval_mutation": lambda approvals: approvals[0].update(environment="staging")},
            "POLICY_APPROVAL_ENVIRONMENT_UNAUTHORIZED",
        ),
        (
            "non_production_scope",
            {"approval_mutation": lambda approvals: approvals[0].update(approval_scope="NON_PRODUCTION")},
            "POLICY_APPROVAL_ENVIRONMENT_UNAUTHORIZED",
        ),
        (
            "wrong_policy_hash",
            {"approval_mutation": lambda approvals: approvals[0].update(policy_hash="0" * 64)},
            "POLICY_APPROVAL_1_HASH_MISMATCH",
        ),
        (
            "wrong_policy_version",
            {"approval_mutation": lambda approvals: approvals[0].update(policy_version="wrong")},
            "POLICY_APPROVAL_VERSION_MISMATCH",
        ),
        (
            "expired_approval",
            {
                "approval_mutation": lambda approvals: approvals[0].update(
                    approved_at="2026-01-01T00:00:00Z",
                    timestamp="2026-01-01T00:00:00Z",
                )
            },
            "POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK",
        ),
        (
            "future_approval",
            {
                "approval_mutation": lambda approvals: approvals[0].update(
                    approved_at="2999-01-01T00:00:00Z",
                    timestamp="2999-01-01T00:00:00Z",
                )
            },
            "POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK",
        ),
        (
            "revoked_approval",
            {"approval_mutation": lambda approvals: approvals[0].update(revoked=True)},
            "POLICY_APPROVAL_REVOKED",
        ),
        (
            "revoked_registered_approver",
            {"registry_mutation": lambda registry, approvals: registry["approvers"][0].update(revoked=True)},
            "POLICY_APPROVAL_APPROVER_REVOKED",
        ),
        (
            "duplicate_nonce",
            {"approval_mutation": lambda approvals: approvals[1].update(nonce=approvals[0]["nonce"])},
            "POLICY_APPROVAL_REUSE_DETECTED",
        ),
        (
            "replayed_nonce",
            {
                "registry_mutation": lambda registry, approvals: registry["replay_registry"]["consumed_nonce_hashes"].append(
                    hashlib.sha256(approvals[0]["nonce"].encode("utf-8")).hexdigest()
                )
            },
            "POLICY_APPROVAL_REUSE_DETECTED",
        ),
        (
            "same_approver_twice",
            {"same_approver": True},
            "POLICY_APPROVAL_DUPLICATE_APPROVER",
        ),
        (
            "same_signing_key_twice",
            {"same_key": True},
            "POLICY_APPROVAL_KEYS_NOT_DISTINCT",
        ),
        (
            "tampered_registry",
            {"tamper_registry_after_signing": True},
            "POLICY_AUTHORITY_APPROVER_REGISTRY_SIGNATURE_INVALID",
        ),
        (
            "stale_registry",
            {"registry_mutation": lambda registry, approvals: registry.update(valid_until="2026-01-01T00:00:00Z")},
            "POLICY_AUTHORITY_APPROVER_REGISTRY_MALFORMED",
        ),
        (
            "stale_revocation_state",
            {"registry_mutation": lambda registry, approvals: registry["revocation_state"].update(checked_at="2026-01-01T00:00:00Z")},
            "POLICY_AUTHORITY_REVOCATION_STATE_STALE",
        ),
        (
            "unavailable_revocation_state",
            {"registry_mutation": lambda registry, approvals: registry["revocation_state"].update(unavailable=True)},
            "POLICY_AUTHORITY_REVOCATION_STATE_UNAVAILABLE",
        ),
        (
            "unavailable_replay_state",
            {"registry_mutation": lambda registry, approvals: registry["replay_registry"].update(unavailable=True)},
            "POLICY_APPROVAL_REPLAY_REGISTRY_UNAVAILABLE",
        ),
        (
            "policy_substitution",
            {"registry_mutation": lambda registry, approvals: registry.update(authority_scope="other_scope")},
            "POLICY_AUTHORITY_APPROVER_REGISTRY_MALFORMED",
        ),
        (
            "approval_substitution",
            {"tamper_approval_after_signing": True},
            "POLICY_APPROVAL_1_SIGNATURE_INVALID",
        ),
    ],
)
def test_production_policy_authority_registry_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
    kwargs: dict,
    expected: str,
) -> None:
    _write_policy_authority_fixture(monkeypatch, tmp_path, **kwargs)
    metadata = policy_validator.load_policy_metadata()

    with pytest.raises(RuntimeError, match=expected):
        policy_validator.validate_approval_artifacts(
            policy_hash=metadata["policy_hash"],
            policy_version=metadata["policy_version"],
        )


def test_missing_policy_authority_registry_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _write_policy_authority_fixture(monkeypatch, tmp_path)
    paths["registry_json"].unlink()
    metadata = policy_validator.load_policy_metadata()

    with pytest.raises(RuntimeError, match="POLICY_AUTHORITY_APPROVER_REGISTRY_MISSING"):
        policy_validator.validate_approval_artifacts(
            policy_hash=metadata["policy_hash"],
            policy_version=metadata["policy_version"],
        )
