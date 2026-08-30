from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from governance.evidence_chain import append_evidence_chain
from governance.evidence_merkle_checkpoint import (
    MERKLE_ERROR_CODES,
    EvidenceMerkleCheckpointError,
    create_merkle_checkpoint,
    explain_merkle_checkpoint,
    load_merkle_error_registry,
    verify_merkle_checkpoint,
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


def _chain() -> dict:
    chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
    return append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:01:00Z")


def test_valid_merkle_checkpoint_generation() -> None:
    chain = _chain()
    checkpoint = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:02:00Z")
    result = verify_merkle_checkpoint(checkpoint, evidence_chain=chain)

    assert result.valid is True
    assert result.errors == ()
    assert checkpoint["leaf_hashes"] == [entry["current_manifest_hash"] for entry in chain["entries"]]
    assert checkpoint["evidence_chain_head_hash"] == chain["entries"][-1]["current_manifest_hash"]


def test_missing_leaves_rejection() -> None:
    checkpoint = create_merkle_checkpoint(_chain(), chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:02:00Z")
    checkpoint["leaf_hashes"] = []

    result = verify_merkle_checkpoint(checkpoint)

    assert result.valid is False
    assert "MERKLE_LEAVES_MISSING" in result.errors


def test_invalid_chain_range_rejection() -> None:
    with pytest.raises(EvidenceMerkleCheckpointError, match="MERKLE_CHAIN_RANGE_INVALID"):
        create_merkle_checkpoint(_chain(), chain_start_position=2, chain_end_position=1, timestamp="2026-05-12T00:02:00Z")

    checkpoint = create_merkle_checkpoint(_chain(), chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:02:00Z")
    checkpoint["chain_end_position"] = 4
    result = verify_merkle_checkpoint(checkpoint)
    assert "MERKLE_CHAIN_RANGE_INVALID" in result.errors


def test_root_mismatch_rejection() -> None:
    checkpoint = create_merkle_checkpoint(_chain(), chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:02:00Z")
    checkpoint["merkle_root"] = "0" * 64

    result = verify_merkle_checkpoint(checkpoint)

    assert result.valid is False
    assert "MERKLE_ROOT_MISMATCH" in result.errors


def test_chain_head_mismatch_rejection() -> None:
    chain = _chain()
    checkpoint = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:02:00Z")
    checkpoint["evidence_chain_head_hash"] = "f" * 64

    result = verify_merkle_checkpoint(checkpoint, evidence_chain=chain)

    assert result.valid is False
    assert "MERKLE_CHAIN_HEAD_MISMATCH" in result.errors


def test_replay_detection() -> None:
    checkpoint = create_merkle_checkpoint(_chain(), chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:02:00Z")
    checkpoint["leaf_hashes"][1] = checkpoint["leaf_hashes"][0]

    result = verify_merkle_checkpoint(checkpoint)

    assert result.valid is False
    assert "MERKLE_CHECKPOINT_REPLAY_DETECTED" in result.errors

    replay_result = verify_merkle_checkpoint(checkpoint, existing_checkpoints=[checkpoint])
    assert "MERKLE_CHECKPOINT_REPLAY_DETECTED" in replay_result.errors


def test_unsafe_diagnostics_rejected() -> None:
    checkpoint = create_merkle_checkpoint(_chain(), chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:02:00Z")
    checkpoint["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_merkle_checkpoint(checkpoint)

    assert result.valid is False
    assert "MERKLE_DIAGNOSTICS_UNSAFE" in result.errors


def test_merkle_error_registry_complete() -> None:
    registry = load_merkle_error_registry(ROOT)

    assert set(MERKLE_ERROR_CODES).issubset(registry)
    assert explain_merkle_checkpoint(ROOT, "MERKLE_ROOT_MISMATCH")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    chain = _chain()
    chain_path = tmp_path / "evidence-chain.json"
    checkpoint_path = tmp_path / "merkle-checkpoint.json"
    chain_path.write_text(json.dumps(chain, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-merkle-checkpoint",
            "--evidence-chain",
            str(chain_path),
            "--chain-start-position",
            "0",
            "--chain-end-position",
            "1",
            "--output",
            str(checkpoint_path),
            "--validation-timestamp",
            "2026-05-12T00:02:00Z",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert checkpoint_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "private_key" not in checkpoint_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-merkle-checkpoint",
            "--merkle-checkpoint",
            str(checkpoint_path),
            "--evidence-chain",
            str(chain_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
