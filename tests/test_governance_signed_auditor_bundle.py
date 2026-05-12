from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.auditor_verification_bundle import create_auditor_verification_bundle
from governance.evidence_chain import append_evidence_chain
from governance.evidence_merkle_checkpoint import create_merkle_checkpoint
from governance.evidence_merkle_consistency import create_merkle_consistency_proof
from governance.evidence_merkle_inclusion import create_merkle_inclusion_proof
from governance.policy_pack import POLICY_PACK_SCHEMA
from governance.policy_parity import build_runtime_decision_record
from governance.policy_proof_bundle import build_policy_proof_bundle
from governance.policy_simulation import DECISION_ALLOW
from governance.proof_timestamp_anchor import anchor_proof_bundle
from governance.rfc3161_timestamp import prepare_rfc3161_request_material
from governance.signed_auditor_bundle import (
    PRIVATE_KEY_ENV,
    SIGNED_AUDITOR_BUNDLE_ERROR_CODES,
    SignedAuditorBundleError,
    create_signed_auditor_bundle,
    explain_signed_auditor_bundle_failure,
    load_signed_auditor_bundle_error_registry,
    signer_key_fingerprint,
    verify_signed_auditor_bundle,
)
from governance.worm_evidence_manifest import prepare_worm_manifest


ROOT = Path(__file__).resolve().parents[1]


def _keypair() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_key


def _trust_policy(public_key: str, *, signer_id: str = "signed-auditor-test-signer") -> dict:
    return {
        "policy_version": "signed-auditor-test-v1",
        "allowed_signers": [
            {
                "signer_id": signer_id,
                "public_key_fingerprint": signer_key_fingerprint(public_key),
                "public_key_pem": public_key,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            }
        ],
        "revoked_fingerprints": [],
    }


def _worm_manifest(policy_id: str = "policy.allow.read") -> dict:
    policy_pack = {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [
            {
                "policy_id": policy_id,
                "risk_level": "low",
                "requires_human_approval": False,
                "fail_closed": True,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                "allow_rules": [{"action": "read", "resource": "ledger"}],
                "deny_rules": [],
            }
        ],
    }
    request = {"action": "read", "resource": "ledger"}
    runtime_record = build_runtime_decision_record(
        decision=DECISION_ALLOW,
        policy_pack=policy_pack,
        request_context=request,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    bundle = build_policy_proof_bundle(
        policy_pack,
        request,
        runtime_record,
        tenant_id="t1",
        environment="test",
        risk_level="low",
        validation_timestamp="2026-05-12T00:00:00Z",
    )
    anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
    rfc3161_request = prepare_rfc3161_request_material(bundle, anchor)
    return prepare_worm_manifest(
        bundle,
        anchor,
        rfc3161_request,
        retention_policy_label="governance-retain-7y",
        created_at="2026-05-12T00:00:00Z",
    )


def _auditor_bundle() -> dict:
    chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
    previous = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=0, timestamp="2026-05-12T00:01:00Z")
    chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:02:00Z")
    current = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:03:00Z")
    return create_auditor_verification_bundle(
        current,
        create_merkle_inclusion_proof(current, leaf_index=1),
        create_merkle_consistency_proof(previous, current),
        verification_scope={"tenant_id": "t1", "environment": "test", "purpose": "offline-audit"},
        timestamp="2026-05-12T00:04:00Z",
    )


def _signed_envelope() -> tuple[dict, dict, dict]:
    private_key, public_key = _keypair()
    policy = _trust_policy(public_key)
    auditor_bundle = _auditor_bundle()
    envelope = create_signed_auditor_bundle(
        auditor_bundle,
        private_key_pem=private_key,
        public_key_pem=public_key,
        signer_id="signed-auditor-test-signer",
        trust_policy=policy,
        signed_at_utc="2026-05-12T00:05:00Z",
    )
    return envelope, auditor_bundle, policy


def test_valid_signed_bundle_envelope() -> None:
    envelope, auditor_bundle, policy = _signed_envelope()
    result = verify_signed_auditor_bundle(envelope, auditor_bundle=auditor_bundle, trust_policy=policy)

    assert result.valid is True
    assert result.errors == ()
    assert envelope["signature_algorithm"] == "Ed25519"
    assert result.auditor_bundle_id == auditor_bundle["bundle_id"]


def test_bundle_hash_mismatch_rejection() -> None:
    envelope, auditor_bundle, policy = _signed_envelope()
    envelope["auditor_bundle_hash"] = "0" * 64

    result = verify_signed_auditor_bundle(envelope, auditor_bundle=auditor_bundle, trust_policy=policy)

    assert result.valid is False
    assert "SIGNED_BUNDLE_HASH_MISMATCH" in result.errors


def test_invalid_signature_rejection() -> None:
    envelope, auditor_bundle, policy = _signed_envelope()
    envelope["signature"] = "ed25519:" + ("A" * 88)

    result = verify_signed_auditor_bundle(envelope, auditor_bundle=auditor_bundle, trust_policy=policy)

    assert result.valid is False
    assert "SIGNED_BUNDLE_SIGNATURE_INVALID" in result.errors


def test_untrusted_signer_rejection() -> None:
    envelope, auditor_bundle, _ = _signed_envelope()
    untrusted_policy = {"policy_version": "signed-auditor-test-v1", "allowed_signers": [], "revoked_fingerprints": []}

    result = verify_signed_auditor_bundle(envelope, auditor_bundle=auditor_bundle, trust_policy=untrusted_policy)

    assert result.valid is False
    assert "SIGNED_BUNDLE_SIGNER_UNTRUSTED" in result.errors


def test_replay_rejection() -> None:
    envelope, auditor_bundle, policy = _signed_envelope()

    result = verify_signed_auditor_bundle(envelope, auditor_bundle=auditor_bundle, trust_policy=policy, existing_envelopes=[envelope])

    assert result.valid is False
    assert "SIGNED_BUNDLE_REPLAY_DETECTED" in result.errors


def test_invalid_scope_rejection() -> None:
    envelope, auditor_bundle, policy = _signed_envelope()
    envelope["verification_scope"] = {"tenant_id": "t1"}

    result = verify_signed_auditor_bundle(envelope, auditor_bundle=auditor_bundle, trust_policy=policy)

    assert result.valid is False
    assert "SIGNED_BUNDLE_SCOPE_INVALID" in result.errors


def test_unsafe_diagnostics_rejected() -> None:
    envelope, auditor_bundle, policy = _signed_envelope()
    envelope["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_signed_auditor_bundle(envelope, auditor_bundle=auditor_bundle, trust_policy=policy)

    assert result.valid is False
    assert "SIGNED_BUNDLE_DIAGNOSTICS_UNSAFE" in result.errors


def test_signed_bundle_error_registry_complete() -> None:
    registry = load_signed_auditor_bundle_error_registry(ROOT)

    assert set(SIGNED_AUDITOR_BUNDLE_ERROR_CODES).issubset(registry)
    assert explain_signed_auditor_bundle_failure(ROOT, "SIGNED_BUNDLE_SIGNATURE_INVALID")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    private_key, public_key = _keypair()
    policy = _trust_policy(public_key)
    auditor_bundle = _auditor_bundle()
    auditor_bundle_path = tmp_path / "auditor-bundle.json"
    trust_policy_path = tmp_path / "trust-policy.json"
    envelope_path = tmp_path / "signed-auditor-bundle.json"
    auditor_bundle_path.write_text(json.dumps(auditor_bundle, sort_keys=True), encoding="utf-8")
    trust_policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
    env = dict(os.environ)
    env[PRIVATE_KEY_ENV] = private_key

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-signed-auditor-bundle",
            "--auditor-bundle",
            str(auditor_bundle_path),
            "--trust-policy",
            str(trust_policy_path),
            "--signer-id",
            "signed-auditor-test-signer",
            "--validation-timestamp",
            "2026-05-12T00:05:00Z",
            "--output",
            str(envelope_path),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert envelope_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout
    assert "PRIVATE KEY" not in envelope_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-signed-auditor-bundle",
            "--signed-auditor-bundle",
            str(envelope_path),
            "--auditor-bundle",
            str(auditor_bundle_path),
            "--trust-policy",
            str(trust_policy_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
