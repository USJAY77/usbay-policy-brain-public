from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from governance.evidence_chain import (
    EVIDENCE_CHAIN_ERROR_CODES,
    EvidenceChainError,
    append_evidence_chain,
    evidence_chain_summary,
    explain_evidence_chain_failure,
    load_evidence_chain_error_registry,
    verify_evidence_chain,
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


def test_valid_append_only_chain_continuity() -> None:
    chain = _chain()
    result = verify_evidence_chain(chain)

    assert result.valid is True
    assert result.errors == ()
    assert result.chain_length == 2
    assert evidence_chain_summary(chain)["latest_chain_hash"] == result.latest_chain_hash


def test_replay_detection() -> None:
    manifest = _worm_manifest("policy.allow.read")
    chain = append_evidence_chain(None, manifest, timestamp="2026-05-12T00:00:00Z")

    with pytest.raises(EvidenceChainError, match="EVIDENCE_CHAIN_REPLAY_DETECTED"):
        append_evidence_chain(chain, manifest, timestamp="2026-05-12T00:01:00Z")

    replayed = dict(chain)
    replayed["entries"] = [dict(chain["entries"][0]), dict(chain["entries"][0])]
    result = verify_evidence_chain(replayed)
    assert "EVIDENCE_CHAIN_REPLAY_DETECTED" in result.errors


def test_broken_previous_hash_rejected() -> None:
    chain = _chain()
    chain["entries"][1]["previous_chain_hash"] = "f" * 64

    result = verify_evidence_chain(chain)

    assert result.valid is False
    assert "EVIDENCE_CHAIN_CONTINUITY_BROKEN" in result.errors


def test_invalid_chain_position_rejected() -> None:
    chain = _chain()
    chain["entries"][1]["chain_position"] = 4

    result = verify_evidence_chain(chain)

    assert result.valid is False
    assert "EVIDENCE_CHAIN_POSITION_INVALID" in result.errors


def test_mismatched_manifest_rejected() -> None:
    chain = _chain()
    chain["entries"][0]["WORM_manifest_hash"] = "0" * 64

    result = verify_evidence_chain(chain)

    assert result.valid is False
    assert "EVIDENCE_CHAIN_CONTINUITY_BROKEN" in result.errors


def test_unsafe_diagnostics_rejected() -> None:
    chain = _chain()
    chain["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_evidence_chain(chain)

    assert result.valid is False
    assert "EVIDENCE_CHAIN_DIAGNOSTICS_UNSAFE" in result.errors


def test_deterministic_chain_replay_verification() -> None:
    first = _chain()
    second = _chain()

    assert first == second
    assert verify_evidence_chain(first).to_dict() == verify_evidence_chain(second).to_dict()


def test_evidence_chain_error_registry_complete() -> None:
    registry = load_evidence_chain_error_registry(ROOT)

    assert set(EVIDENCE_CHAIN_ERROR_CODES).issubset(registry)
    assert explain_evidence_chain_failure(ROOT, "EVIDENCE_CHAIN_REPLAY_DETECTED")["fail_closed_reason"]


def test_append_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    manifest = _worm_manifest("policy.allow.read")
    manifest_path = tmp_path / "worm-manifest.json"
    chain_path = tmp_path / "evidence-chain.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    appended = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "append-evidence-chain",
            "--worm-manifest",
            str(manifest_path),
            "--output",
            str(chain_path),
            "--validation-timestamp",
            "2026-05-12T00:00:00Z",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert appended.returncode == 0
    assert chain_path.is_file()
    assert "approval_contents" not in appended.stdout
    assert "private_key" not in chain_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-evidence-chain",
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
