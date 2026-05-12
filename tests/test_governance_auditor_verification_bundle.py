from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from governance.auditor_verification_bundle import (
    AUDITOR_BUNDLE_ERROR_CODES,
    AuditorVerificationBundleError,
    create_auditor_verification_bundle,
    explain_auditor_bundle_failure,
    load_auditor_bundle_error_registry,
    verify_auditor_verification_bundle,
)
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
from governance.worm_evidence_manifest import prepare_worm_manifest


ROOT = Path(__file__).resolve().parents[1]


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


def _evidence() -> tuple[dict, dict, dict, dict]:
    chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
    previous = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=0, timestamp="2026-05-12T00:01:00Z")
    chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:02:00Z")
    current = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:03:00Z")
    inclusion = create_merkle_inclusion_proof(current, leaf_index=1)
    consistency = create_merkle_consistency_proof(previous, current)
    return current, inclusion, consistency, previous


def _bundle() -> dict:
    checkpoint, inclusion, consistency, _ = _evidence()
    return create_auditor_verification_bundle(
        checkpoint,
        inclusion,
        consistency,
        verification_scope={"tenant_id": "t1", "environment": "test", "purpose": "offline-audit"},
        timestamp="2026-05-12T00:04:00Z",
    )


def test_valid_auditor_bundle_verification() -> None:
    bundle = _bundle()
    result = verify_auditor_verification_bundle(bundle)

    assert result.valid is True
    assert result.errors == ()
    assert result.checkpoint_id == bundle["checkpoint_id"]
    assert result.merkle_root == bundle["merkle_root"]


def test_missing_checkpoint_rejection() -> None:
    checkpoint, inclusion, consistency, _ = _evidence()

    with pytest.raises(AuditorVerificationBundleError, match="AUDITOR_BUNDLE_CHECKPOINT_MISSING"):
        create_auditor_verification_bundle({}, inclusion, consistency, verification_scope={"purpose": "offline-audit"})

    bundle = create_auditor_verification_bundle(
        checkpoint,
        inclusion,
        consistency,
        verification_scope={"purpose": "offline-audit"},
        timestamp="2026-05-12T00:04:00Z",
    )
    bundle["checkpoint_id"] = ""
    result = verify_auditor_verification_bundle(bundle)
    assert "AUDITOR_BUNDLE_CHECKPOINT_MISSING" in result.errors


def test_missing_inclusion_proof_rejection() -> None:
    checkpoint, _, consistency, _ = _evidence()

    with pytest.raises(AuditorVerificationBundleError, match="AUDITOR_BUNDLE_INCLUSION_MISSING"):
        create_auditor_verification_bundle(checkpoint, {}, consistency, verification_scope={"purpose": "offline-audit"})

    bundle = _bundle()
    bundle["inclusion_proof_summary"] = {}
    result = verify_auditor_verification_bundle(bundle)
    assert "AUDITOR_BUNDLE_INCLUSION_MISSING" in result.errors


def test_missing_consistency_proof_rejection() -> None:
    checkpoint, inclusion, _, _ = _evidence()

    with pytest.raises(AuditorVerificationBundleError, match="AUDITOR_BUNDLE_CONSISTENCY_MISSING"):
        create_auditor_verification_bundle(checkpoint, inclusion, {}, verification_scope={"purpose": "offline-audit"})

    bundle = _bundle()
    bundle["consistency_proof_summary"] = {}
    result = verify_auditor_verification_bundle(bundle)
    assert "AUDITOR_BUNDLE_CONSISTENCY_MISSING" in result.errors


def test_invalid_scope_rejection() -> None:
    checkpoint, inclusion, consistency, _ = _evidence()

    with pytest.raises(AuditorVerificationBundleError, match="AUDITOR_BUNDLE_SCOPE_INVALID"):
        create_auditor_verification_bundle(checkpoint, inclusion, consistency, verification_scope={})

    bundle = _bundle()
    bundle["verification_scope"] = {"tenant_id": "t1"}
    result = verify_auditor_verification_bundle(bundle)
    assert "AUDITOR_BUNDLE_SCOPE_INVALID" in result.errors


def test_hash_mismatch_rejection() -> None:
    bundle = _bundle()
    bundle["merkle_root"] = "0" * 64

    result = verify_auditor_verification_bundle(bundle)

    assert result.valid is False
    assert "AUDITOR_BUNDLE_HASH_MISMATCH" in result.errors


def test_replay_rejection() -> None:
    bundle = _bundle()

    result = verify_auditor_verification_bundle(bundle, existing_bundles=[bundle])

    assert result.valid is False
    assert "AUDITOR_BUNDLE_REPLAY_DETECTED" in result.errors


def test_unsafe_diagnostics_rejected() -> None:
    bundle = _bundle()
    bundle["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_auditor_verification_bundle(bundle)

    assert result.valid is False
    assert "AUDITOR_BUNDLE_DIAGNOSTICS_UNSAFE" in result.errors


def test_auditor_bundle_error_registry_complete() -> None:
    registry = load_auditor_bundle_error_registry(ROOT)

    assert set(AUDITOR_BUNDLE_ERROR_CODES).issubset(registry)
    assert explain_auditor_bundle_failure(ROOT, "AUDITOR_BUNDLE_HASH_MISMATCH")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    checkpoint, inclusion, consistency, _ = _evidence()
    checkpoint_path = tmp_path / "checkpoint.json"
    inclusion_path = tmp_path / "inclusion.json"
    consistency_path = tmp_path / "consistency.json"
    bundle_path = tmp_path / "auditor-bundle.json"
    checkpoint_path.write_text(json.dumps(checkpoint, sort_keys=True), encoding="utf-8")
    inclusion_path.write_text(json.dumps(inclusion, sort_keys=True), encoding="utf-8")
    consistency_path.write_text(json.dumps(consistency, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-auditor-verification-bundle",
            "--merkle-checkpoint",
            str(checkpoint_path),
            "--merkle-inclusion-proof",
            str(inclusion_path),
            "--merkle-consistency-proof",
            str(consistency_path),
            "--verification-purpose",
            "offline-audit",
            "--tenant-id",
            "t1",
            "--environment",
            "test",
            "--validation-timestamp",
            "2026-05-12T00:04:00Z",
            "--output",
            str(bundle_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert bundle_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "private_key" not in bundle_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-auditor-verification-bundle",
            "--auditor-bundle",
            str(bundle_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
