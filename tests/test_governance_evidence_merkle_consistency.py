from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from governance.evidence_chain import append_evidence_chain
from governance.evidence_merkle_checkpoint import create_merkle_checkpoint
from governance.evidence_merkle_consistency import (
    MERKLE_CONSISTENCY_ERROR_CODES,
    EvidenceMerkleConsistencyError,
    create_merkle_consistency_proof,
    explain_merkle_consistency_failure,
    load_merkle_consistency_error_registry,
    verify_merkle_consistency_proof,
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


def _checkpoints() -> tuple[dict, dict]:
    chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
    previous = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=0, timestamp="2026-05-12T00:01:00Z")
    chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:02:00Z")
    current = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:03:00Z")
    return previous, current


def test_valid_consistency_proof_between_checkpoints() -> None:
    previous, current = _checkpoints()
    proof = create_merkle_consistency_proof(previous, current)
    result = verify_merkle_consistency_proof(proof, previous_checkpoint=previous, current_checkpoint=current)

    assert result.valid is True
    assert result.errors == ()
    assert proof["previous_merkle_root"] == previous["merkle_root"]
    assert proof["current_merkle_root"] == current["merkle_root"]


def test_missing_previous_checkpoint_rejection() -> None:
    _, current = _checkpoints()

    with pytest.raises(EvidenceMerkleConsistencyError, match="MERKLE_CONSISTENCY_PREVIOUS_MISSING"):
        create_merkle_consistency_proof({}, current)

    proof = create_merkle_consistency_proof(*_checkpoints())
    proof["previous_checkpoint_id"] = ""
    result = verify_merkle_consistency_proof(proof)
    assert "MERKLE_CONSISTENCY_PREVIOUS_MISSING" in result.errors


def test_missing_current_checkpoint_rejection() -> None:
    previous, _ = _checkpoints()

    with pytest.raises(EvidenceMerkleConsistencyError, match="MERKLE_CONSISTENCY_CURRENT_MISSING"):
        create_merkle_consistency_proof(previous, {})

    proof = create_merkle_consistency_proof(*_checkpoints())
    proof["current_checkpoint_id"] = ""
    result = verify_merkle_consistency_proof(proof)
    assert "MERKLE_CONSISTENCY_CURRENT_MISSING" in result.errors


def test_invalid_range_rejection() -> None:
    previous, current = _checkpoints()

    with pytest.raises(EvidenceMerkleConsistencyError, match="MERKLE_CONSISTENCY_RANGE_INVALID"):
        create_merkle_consistency_proof(current, previous)

    proof = create_merkle_consistency_proof(previous, current)
    proof["current_chain_end_position"] = proof["previous_chain_end_position"]
    result = verify_merkle_consistency_proof(proof)
    assert "MERKLE_CONSISTENCY_RANGE_INVALID" in result.errors


def test_root_mismatch_rejection() -> None:
    proof = create_merkle_consistency_proof(*_checkpoints())
    proof["current_merkle_root"] = "0" * 64

    result = verify_merkle_consistency_proof(proof)

    assert result.valid is False
    assert "MERKLE_CONSISTENCY_ROOT_MISMATCH" in result.errors


def test_malformed_consistency_path_rejection() -> None:
    proof = create_merkle_consistency_proof(*_checkpoints())
    proof["consistency_path"] = {"previous_leaf_hashes": ["not-a-hash"], "appended_leaf_hashes": []}

    result = verify_merkle_consistency_proof(proof)

    assert result.valid is False
    assert "MERKLE_CONSISTENCY_PATH_INVALID" in result.errors


def test_replay_detection() -> None:
    proof = create_merkle_consistency_proof(*_checkpoints())

    replay_result = verify_merkle_consistency_proof(proof, existing_proofs=[proof])
    assert replay_result.valid is False
    assert "MERKLE_CONSISTENCY_REPLAY_DETECTED" in replay_result.errors

    proof["current_checkpoint_id"] = proof["previous_checkpoint_id"]
    result = verify_merkle_consistency_proof(proof)
    assert "MERKLE_CONSISTENCY_REPLAY_DETECTED" in result.errors


def test_unsafe_diagnostics_rejected() -> None:
    proof = create_merkle_consistency_proof(*_checkpoints())
    proof["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_merkle_consistency_proof(proof)

    assert result.valid is False
    assert "MERKLE_CONSISTENCY_DIAGNOSTICS_UNSAFE" in result.errors


def test_merkle_consistency_error_registry_complete() -> None:
    registry = load_merkle_consistency_error_registry(ROOT)

    assert set(MERKLE_CONSISTENCY_ERROR_CODES).issubset(registry)
    assert explain_merkle_consistency_failure(ROOT, "MERKLE_CONSISTENCY_ROOT_MISMATCH")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    previous, current = _checkpoints()
    previous_path = tmp_path / "previous-checkpoint.json"
    current_path = tmp_path / "current-checkpoint.json"
    proof_path = tmp_path / "consistency-proof.json"
    previous_path.write_text(json.dumps(previous, sort_keys=True), encoding="utf-8")
    current_path.write_text(json.dumps(current, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-merkle-consistency-proof",
            "--previous-merkle-checkpoint",
            str(previous_path),
            "--current-merkle-checkpoint",
            str(current_path),
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
            "verify-merkle-consistency-proof",
            "--merkle-consistency-proof",
            str(proof_path),
            "--previous-merkle-checkpoint",
            str(previous_path),
            "--current-merkle-checkpoint",
            str(current_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
