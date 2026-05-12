from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from governance.evidence_chain import append_evidence_chain
from governance.evidence_merkle_checkpoint import create_merkle_checkpoint
from governance.evidence_merkle_inclusion import (
    MERKLE_INCLUSION_ERROR_CODES,
    EvidenceMerkleInclusionError,
    create_merkle_inclusion_proof,
    explain_merkle_inclusion_failure,
    load_merkle_inclusion_error_registry,
    verify_merkle_inclusion_proof,
)
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


def _checkpoint() -> dict:
    chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
    chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:01:00Z")
    return create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:02:00Z")


def test_valid_inclusion_proof() -> None:
    checkpoint = _checkpoint()
    proof = create_merkle_inclusion_proof(checkpoint, leaf_index=1)
    result = verify_merkle_inclusion_proof(proof, checkpoint=checkpoint)

    assert result.valid is True
    assert result.errors == ()
    assert proof["leaf_hash"] == checkpoint["leaf_hashes"][1]
    assert proof["merkle_root"] == checkpoint["merkle_root"]


def test_missing_leaf_rejection() -> None:
    proof = create_merkle_inclusion_proof(_checkpoint(), leaf_index=0)
    proof["leaf_hash"] = ""

    result = verify_merkle_inclusion_proof(proof)

    assert result.valid is False
    assert "MERKLE_INCLUSION_LEAF_MISSING" in result.errors


def test_invalid_index_rejection() -> None:
    with pytest.raises(EvidenceMerkleInclusionError, match="MERKLE_INCLUSION_INDEX_INVALID"):
        create_merkle_inclusion_proof(_checkpoint(), leaf_index=9)

    proof = create_merkle_inclusion_proof(_checkpoint(), leaf_index=0)
    proof["leaf_index"] = -1
    result = verify_merkle_inclusion_proof(proof)
    assert "MERKLE_INCLUSION_INDEX_INVALID" in result.errors


def test_malformed_sibling_path_rejection() -> None:
    proof = create_merkle_inclusion_proof(_checkpoint(), leaf_index=0)
    proof["sibling_path"] = [{"direction": "sideways", "hash": "0" * 64}]

    result = verify_merkle_inclusion_proof(proof)

    assert result.valid is False
    assert "MERKLE_INCLUSION_PATH_INVALID" in result.errors


def test_root_mismatch_rejection() -> None:
    proof = create_merkle_inclusion_proof(_checkpoint(), leaf_index=0)
    proof["merkle_root"] = "0" * 64

    result = verify_merkle_inclusion_proof(proof)

    assert result.valid is False
    assert "MERKLE_INCLUSION_ROOT_MISMATCH" in result.errors


def test_checkpoint_mismatch_rejection() -> None:
    checkpoint = _checkpoint()
    proof = create_merkle_inclusion_proof(checkpoint, leaf_index=0)
    proof["checkpoint_id"] = "f" * 64

    result = verify_merkle_inclusion_proof(proof, checkpoint=checkpoint)

    assert result.valid is False
    assert "MERKLE_INCLUSION_CHECKPOINT_MISMATCH" in result.errors


def test_unsafe_diagnostics_rejected() -> None:
    proof = create_merkle_inclusion_proof(_checkpoint(), leaf_index=0)
    proof["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_merkle_inclusion_proof(proof)

    assert result.valid is False
    assert "MERKLE_INCLUSION_DIAGNOSTICS_UNSAFE" in result.errors


def test_merkle_inclusion_error_registry_complete() -> None:
    registry = load_merkle_inclusion_error_registry(ROOT)

    assert set(MERKLE_INCLUSION_ERROR_CODES).issubset(registry)
    assert explain_merkle_inclusion_failure(ROOT, "MERKLE_INCLUSION_ROOT_MISMATCH")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    checkpoint = _checkpoint()
    checkpoint_path = tmp_path / "merkle-checkpoint.json"
    proof_path = tmp_path / "inclusion-proof.json"
    checkpoint_path.write_text(json.dumps(checkpoint, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-merkle-inclusion-proof",
            "--merkle-checkpoint",
            str(checkpoint_path),
            "--leaf-index",
            "1",
            "--output",
            str(proof_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert proof_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "private_key" not in proof_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-merkle-inclusion-proof",
            "--merkle-inclusion-proof",
            str(proof_path),
            "--merkle-checkpoint",
            str(checkpoint_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
