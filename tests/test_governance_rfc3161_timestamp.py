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
from governance.proof_timestamp_anchor import anchor_proof_bundle
from governance.rfc3161_timestamp import (
    RFC3161_ERROR_CODES,
    RFC3161TimestampError,
    explain_rfc3161_preflight,
    load_rfc3161_error_registry,
    prepare_rfc3161_request_material,
    verify_rfc3161_request_material,
)


ROOT = Path(__file__).resolve().parents[1]


def _policy_pack() -> dict:
    return {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [
            {
                "policy_id": "policy.allow.read",
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


def _bundle_and_anchor() -> tuple[dict, dict]:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger"}
    runtime_record = build_runtime_decision_record(
        decision=DECISION_ALLOW,
        policy_pack=pack,
        request_context=request,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    bundle = build_policy_proof_bundle(
        pack,
        request,
        runtime_record,
        tenant_id="t1",
        environment="test",
        risk_level="low",
        validation_timestamp="2026-05-12T00:00:00Z",
    )
    return bundle, anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")


def test_valid_rfc3161_request_material_is_deterministic() -> None:
    bundle, anchor = _bundle_and_anchor()

    first = prepare_rfc3161_request_material(bundle, anchor)
    second = prepare_rfc3161_request_material(bundle, anchor)
    result = verify_rfc3161_request_material(first)

    assert first == second
    assert result.valid is True
    assert result.errors == ()
    assert first["tsa_response_status"] == "NOT_REQUESTED"


def test_missing_bundle_hash_rejected() -> None:
    bundle, anchor = _bundle_and_anchor()
    request = prepare_rfc3161_request_material(bundle, anchor)
    request["proof_bundle_hash"] = ""

    result = verify_rfc3161_request_material(request)

    assert result.valid is False
    assert "RFC3161_BUNDLE_HASH_MISSING" in result.errors


def test_missing_timestamp_anchor_hash_rejected() -> None:
    bundle, anchor = _bundle_and_anchor()
    request = prepare_rfc3161_request_material(bundle, anchor)
    request["timestamp_anchor_hash"] = ""

    result = verify_rfc3161_request_material(request)

    assert result.valid is False
    assert "RFC3161_ANCHOR_HASH_MISSING" in result.errors


def test_malformed_nonce_rejected() -> None:
    bundle, anchor = _bundle_and_anchor()

    with pytest.raises(RFC3161TimestampError, match="RFC3161_NONCE_INVALID"):
        prepare_rfc3161_request_material(bundle, anchor, nonce="not-a-hex-nonce")

    request = prepare_rfc3161_request_material(bundle, anchor)
    request["nonce"] = "bad"
    result = verify_rfc3161_request_material(request)
    assert "RFC3161_NONCE_INVALID" in result.errors


def test_unsafe_diagnostics_rejected() -> None:
    bundle, anchor = _bundle_and_anchor()
    request = prepare_rfc3161_request_material(bundle, anchor)
    request["redacted_metadata_summary"] = {"approval_contents": "do-not-export"}

    result = verify_rfc3161_request_material(request)

    assert result.valid is False
    assert "RFC3161_DIAGNOSTICS_UNSAFE" in result.errors


def test_unverifiable_request_fails_closed() -> None:
    bundle, anchor = _bundle_and_anchor()
    request = prepare_rfc3161_request_material(bundle, anchor)
    request["canonical_request_digest"] = "0" * 64

    result = verify_rfc3161_request_material(request)

    assert result.valid is False
    assert "RFC3161_REQUEST_INVALID" in result.errors


def test_tsa_response_state_rejected_until_live_verification_exists() -> None:
    bundle, anchor = _bundle_and_anchor()
    request = prepare_rfc3161_request_material(bundle, anchor)
    request["tsa_response_status"] = "PRESENT"

    result = verify_rfc3161_request_material(request)

    assert result.valid is False
    assert "RFC3161_TSA_RESPONSE_UNVERIFIED" in result.errors


def test_rfc3161_error_registry_complete() -> None:
    registry = load_rfc3161_error_registry(ROOT)

    assert set(RFC3161_ERROR_CODES).issubset(registry)
    assert explain_rfc3161_preflight(ROOT, "RFC3161_TSA_RESPONSE_UNVERIFIED")["fail_closed_reason"]


def test_prepare_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    bundle, anchor = _bundle_and_anchor()
    bundle_path = tmp_path / "proof-bundle.json"
    anchor_path = tmp_path / "timestamp-anchor.json"
    request_path = tmp_path / "rfc3161-request.json"
    bundle_path.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
    anchor_path.write_text(json.dumps(anchor, sort_keys=True), encoding="utf-8")

    prepared = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "prepare-rfc3161-request",
            "--proof-bundle",
            str(bundle_path),
            "--timestamp-anchor",
            str(anchor_path),
            "--output",
            str(request_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert prepared.returncode == 0
    assert request_path.is_file()
    assert "approval_contents" not in prepared.stdout
    assert "private_key" not in request_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-rfc3161-request",
            "--rfc3161-request",
            str(request_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
