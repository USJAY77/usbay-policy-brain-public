from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from governance.policy_pack import POLICY_PACK_SCHEMA
from governance.policy_parity import build_runtime_decision_record
from governance.policy_proof_bundle import build_policy_proof_bundle
from governance.policy_simulation import DECISION_ALLOW
from governance.proof_timestamp_anchor import (
    TIMESTAMP_ANCHOR_ERROR_CODES,
    ProofTimestampAnchorError,
    anchor_proof_bundle,
    explain_timestamp_anchor,
    load_timestamp_anchor_error_registry,
    verify_proof_timestamp_anchor,
)


ROOT = Path(__file__).resolve().parents[1]


def _policy_pack(policy_id: str = "policy.allow.read") -> dict:
    return {
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


def _proof_bundle(policy_id: str = "policy.allow.read") -> dict:
    pack = _policy_pack(policy_id)
    request = {"action": "read", "resource": "ledger"}
    runtime_record = build_runtime_decision_record(
        decision=DECISION_ALLOW,
        policy_pack=pack,
        request_context=request,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    return build_policy_proof_bundle(
        pack,
        request,
        runtime_record,
        tenant_id="t1",
        environment="test",
        risk_level="low",
        validation_timestamp="2026-05-12T00:00:00Z",
    )


def test_valid_timestamp_anchor() -> None:
    bundle = _proof_bundle()
    anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
    result = verify_proof_timestamp_anchor(anchor, proof_bundle=bundle)

    assert result.valid is True
    assert result.errors == ()
    assert result.timestamp == "2026-05-12T00:00:00Z"
    assert anchor["validation_status"] == "VERIFIED"


def test_missing_bundle_hash_rejected() -> None:
    anchor = anchor_proof_bundle(_proof_bundle(), timestamp="2026-05-12T00:00:00Z")
    anchor["proof_bundle_hash"] = ""

    result = verify_proof_timestamp_anchor(anchor)

    assert result.valid is False
    assert "TIMESTAMP_BUNDLE_HASH_MISSING" in result.errors


def test_malformed_timestamp_payload_rejected() -> None:
    anchor = anchor_proof_bundle(_proof_bundle(), timestamp="2026-05-12T00:00:00Z")
    anchor["canonical_timestamp_payload"]["validation_status"] = "TAMPERED"

    result = verify_proof_timestamp_anchor(anchor)

    assert result.valid is False
    assert "TIMESTAMP_PAYLOAD_INVALID" in result.errors


def test_invalid_clock_rejected() -> None:
    with pytest.raises(ProofTimestampAnchorError, match="TIMESTAMP_CLOCK_INVALID"):
        anchor_proof_bundle(_proof_bundle(), timestamp="2026-05-12T00:00:00+01:00")


def test_unsafe_diagnostics_rejected() -> None:
    anchor = anchor_proof_bundle(_proof_bundle(), timestamp="2026-05-12T00:00:00Z")
    anchor["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_proof_timestamp_anchor(anchor)

    assert result.valid is False
    assert "TIMESTAMP_DIAGNOSTICS_UNSAFE" in result.errors


def test_unverifiable_anchor_fails_closed() -> None:
    anchor = anchor_proof_bundle(_proof_bundle(), timestamp="2026-05-12T00:00:00Z")
    anchor["anchor_hash"] = "0" * 64

    result = verify_proof_timestamp_anchor(anchor)

    assert result.valid is False
    assert "TIMESTAMP_ANCHOR_UNVERIFIED" in result.errors


def test_timestamp_replay_against_different_bundle_rejected() -> None:
    anchor = anchor_proof_bundle(_proof_bundle("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
    replay_bundle = _proof_bundle("policy.allow.other")

    result = verify_proof_timestamp_anchor(anchor, proof_bundle=replay_bundle)

    assert result.valid is False
    assert "TIMESTAMP_ANCHOR_UNVERIFIED" in result.errors


def test_timestamp_anchor_error_registry_complete() -> None:
    registry = load_timestamp_anchor_error_registry(ROOT)

    assert set(TIMESTAMP_ANCHOR_ERROR_CODES).issubset(registry)
    assert explain_timestamp_anchor(ROOT, "TIMESTAMP_ANCHOR_UNVERIFIED")["fail_closed_reason"]


def test_anchor_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    bundle_path = tmp_path / "proof-bundle.json"
    anchor_path = tmp_path / "proof-timestamp-anchor.json"
    bundle_path.write_text(json.dumps(_proof_bundle(), sort_keys=True), encoding="utf-8")

    anchored = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "anchor-proof-bundle",
            "--proof-bundle",
            str(bundle_path),
            "--output",
            str(anchor_path),
            "--validation-timestamp",
            "2026-05-12T00:00:00Z",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert anchored.returncode == 0
    assert anchor_path.is_file()
    assert "approval_contents" not in anchored.stdout
    assert "private_key" not in anchor_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-proof-timestamp",
            "--timestamp-anchor",
            str(anchor_path),
            "--proof-bundle",
            str(bundle_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
