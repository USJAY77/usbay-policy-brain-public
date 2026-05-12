from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from governance.policy_pack import POLICY_PACK_SCHEMA
from governance.policy_parity import build_runtime_decision_record
from governance.policy_proof_bundle import (
    PROOF_BUNDLE_ERROR_CODES,
    PolicyProofBundleError,
    build_policy_proof_bundle,
    explain_proof_bundle,
    load_proof_bundle_error_registry,
    verify_policy_proof_bundle,
)
from governance.policy_simulation import DECISION_ALLOW


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


def _runtime_record(pack: dict, request: dict) -> dict:
    return build_runtime_decision_record(
        decision=DECISION_ALLOW,
        policy_pack=pack,
        request_context=request,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )


def _bundle() -> dict:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger"}
    return build_policy_proof_bundle(
        pack,
        request,
        _runtime_record(pack, request),
        tenant_id="t1",
        environment="test",
        risk_level="low",
        validation_timestamp="2026-05-12T00:00:00Z",
    )


def test_valid_proof_bundle_export_and_verify() -> None:
    bundle = _bundle()
    result = verify_policy_proof_bundle(bundle)

    assert result.valid is True
    assert result.errors == ()
    assert bundle["simulation_decision"] == DECISION_ALLOW
    assert bundle["runtime_parity_result"]["valid"] is True
    assert bundle["fail_closed_status"]["enforced"] is True


def test_missing_policy_hash_rejected() -> None:
    bundle = _bundle()
    del bundle["policy_pack_hash"]
    result = verify_policy_proof_bundle(bundle)

    assert result.valid is False
    assert "PROOF_POLICY_HASH_MISSING" in result.errors


def test_missing_context_hash_rejected() -> None:
    bundle = _bundle()
    bundle["request_context_hash"] = ""
    result = verify_policy_proof_bundle(bundle)

    assert result.valid is False
    assert "PROOF_CONTEXT_HASH_MISSING" in result.errors


def test_unsafe_diagnostics_rejected() -> None:
    bundle = _bundle()
    bundle["redacted_diagnostics_summary"] = {"approval_contents": "do-not-export"}
    result = verify_policy_proof_bundle(bundle)

    assert result.valid is False
    assert "PROOF_DIAGNOSTICS_UNSAFE" in result.errors


def test_unverifiable_parity_rejected_during_export() -> None:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger"}
    runtime_record = _runtime_record(pack, request)
    runtime_record["policy_hash"] = "0" * 64

    with pytest.raises(PolicyProofBundleError, match="PROOF_PARITY_UNVERIFIED"):
        build_policy_proof_bundle(
            pack,
            request,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
        )


def test_missing_runtime_policy_hash_rejected_during_export() -> None:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger"}
    runtime_record = _runtime_record(pack, request)
    del runtime_record["policy_hash"]

    with pytest.raises(PolicyProofBundleError, match="PROOF_POLICY_HASH_MISSING"):
        build_policy_proof_bundle(
            pack,
            request,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
        )


def test_redaction_enforcement_excludes_raw_payload() -> None:
    bundle = _bundle()
    encoded = json.dumps(bundle, sort_keys=True)

    assert "approval_contents" not in encoded
    assert "private_key" not in encoded
    assert ("BEGIN " + "PRIVATE KEY") not in encoded
    assert '"action":"read"' not in encoded


def test_proof_bundle_error_registry_complete() -> None:
    registry = load_proof_bundle_error_registry(ROOT)

    assert set(PROOF_BUNDLE_ERROR_CODES).issubset(registry)
    assert explain_proof_bundle(ROOT, "PROOF_PARITY_UNVERIFIED")["fail_closed_reason"]


def test_export_and_verify_cli_redacts_bundle(tmp_path: Path) -> None:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger", "approval_contents": "do-not-print"}
    runtime_record = _runtime_record(pack, request)
    pack_path = tmp_path / "pack.json"
    request_path = tmp_path / "request.json"
    runtime_path = tmp_path / "runtime.json"
    bundle_path = tmp_path / "policy-proof-bundle.json"
    pack_path.write_text(json.dumps(pack, sort_keys=True), encoding="utf-8")
    request_path.write_text(json.dumps(request, sort_keys=True), encoding="utf-8")
    runtime_path.write_text(json.dumps(runtime_record, sort_keys=True), encoding="utf-8")

    export = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "export-policy-proof-bundle",
            "--policy-pack",
            str(pack_path),
            "--request-context",
            str(request_path),
            "--runtime-decision",
            str(runtime_path),
            "--tenant-id",
            "t1",
            "--environment",
            "test",
            "--output",
            str(bundle_path),
            "--validation-timestamp",
            "2026-05-12T00:00:00Z",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert export.returncode == 0
    assert bundle_path.is_file()
    assert "do-not-print" not in export.stdout
    assert "approval_contents" not in bundle_path.read_text(encoding="utf-8")

    verify = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-policy-proof-bundle",
            "--proof-bundle",
            str(bundle_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verify.returncode == 0
    assert '"valid":true' in verify.stdout
