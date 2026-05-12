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
from governance.rfc3161_timestamp import prepare_rfc3161_request_material
from governance.worm_evidence_manifest import (
    WORM_ERROR_CODES,
    WORMEvidenceManifestError,
    explain_worm_manifest,
    load_worm_error_registry,
    prepare_worm_manifest,
    verify_worm_manifest,
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


def _evidence(policy_id: str = "policy.allow.read") -> tuple[dict, dict, dict]:
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
    bundle = build_policy_proof_bundle(
        pack,
        request,
        runtime_record,
        tenant_id="t1",
        environment="test",
        risk_level="low",
        validation_timestamp="2026-05-12T00:00:00Z",
    )
    anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
    return bundle, anchor, prepare_rfc3161_request_material(bundle, anchor)


def _manifest() -> dict:
    bundle, anchor, request = _evidence()
    return prepare_worm_manifest(
        bundle,
        anchor,
        request,
        retention_policy_label="governance-retain-7y",
        created_at="2026-05-12T00:00:00Z",
    )


def test_valid_worm_manifest_preparation_is_deterministic() -> None:
    bundle, anchor, request = _evidence()
    first = prepare_worm_manifest(
        bundle,
        anchor,
        request,
        retention_policy_label="governance-retain-7y",
        created_at="2026-05-12T00:00:00Z",
    )
    second = prepare_worm_manifest(
        bundle,
        anchor,
        request,
        retention_policy_label="governance-retain-7y",
        created_at="2026-05-12T00:00:00Z",
    )
    result = verify_worm_manifest(first, proof_bundle=bundle, timestamp_anchor=anchor, rfc3161_request=request)

    assert first == second
    assert result.valid is True
    assert result.errors == ()
    assert first["entries"][0]["retention_policy_label"] == "governance-retain-7y"


def test_missing_proof_bundle_hash_rejected() -> None:
    manifest = _manifest()
    manifest["entries"][0]["proof_bundle_hash"] = ""

    result = verify_worm_manifest(manifest)

    assert result.valid is False
    assert "WORM_PROOF_BUNDLE_HASH_MISSING" in result.errors


def test_missing_timestamp_anchor_rejected() -> None:
    manifest = _manifest()
    manifest["entries"][0]["timestamp_anchor_hash"] = ""

    result = verify_worm_manifest(manifest)

    assert result.valid is False
    assert "WORM_TIMESTAMP_ANCHOR_MISSING" in result.errors


def test_missing_rfc3161_digest_rejected() -> None:
    manifest = _manifest()
    manifest["entries"][0]["rfc3161_request_digest"] = ""

    result = verify_worm_manifest(manifest)

    assert result.valid is False
    assert "WORM_RFC3161_DIGEST_MISSING" in result.errors


def test_missing_retention_policy_rejected() -> None:
    bundle, anchor, request = _evidence()

    with pytest.raises(WORMEvidenceManifestError, match="WORM_RETENTION_POLICY_MISSING"):
        prepare_worm_manifest(bundle, anchor, request, retention_policy_label="")

    manifest = _manifest()
    manifest["entries"][0]["retention_policy_label"] = ""
    result = verify_worm_manifest(manifest)
    assert "WORM_RETENTION_POLICY_MISSING" in result.errors


def test_unsafe_diagnostics_rejected() -> None:
    manifest = _manifest()
    manifest["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_worm_manifest(manifest)

    assert result.valid is False
    assert "WORM_DIAGNOSTICS_UNSAFE" in result.errors


def test_manifest_verification_replay_rejected() -> None:
    bundle, anchor, request = _evidence("policy.allow.read")
    replay_bundle, _replay_anchor, _replay_request = _evidence("policy.allow.other")
    manifest = prepare_worm_manifest(
        bundle,
        anchor,
        request,
        retention_policy_label="governance-retain-7y",
        created_at="2026-05-12T00:00:00Z",
    )

    result = verify_worm_manifest(manifest, proof_bundle=replay_bundle, timestamp_anchor=anchor, rfc3161_request=request)

    assert result.valid is False
    assert "WORM_MANIFEST_INVALID" in result.errors


def test_worm_error_registry_complete() -> None:
    registry = load_worm_error_registry(ROOT)

    assert set(WORM_ERROR_CODES).issubset(registry)
    assert explain_worm_manifest(ROOT, "WORM_MANIFEST_INVALID")["fail_closed_reason"]


def test_prepare_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    bundle, anchor, request = _evidence()
    bundle_path = tmp_path / "proof-bundle.json"
    anchor_path = tmp_path / "timestamp-anchor.json"
    rfc3161_path = tmp_path / "rfc3161-request.json"
    manifest_path = tmp_path / "worm-manifest.json"
    bundle_path.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
    anchor_path.write_text(json.dumps(anchor, sort_keys=True), encoding="utf-8")
    rfc3161_path.write_text(json.dumps(request, sort_keys=True), encoding="utf-8")

    prepared = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "prepare-worm-manifest",
            "--proof-bundle",
            str(bundle_path),
            "--timestamp-anchor",
            str(anchor_path),
            "--rfc3161-request",
            str(rfc3161_path),
            "--retention-policy-label",
            "governance-retain-7y",
            "--output",
            str(manifest_path),
            "--validation-timestamp",
            "2026-05-12T00:00:00Z",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert prepared.returncode == 0
    assert manifest_path.is_file()
    assert "approval_contents" not in prepared.stdout
    assert "private_key" not in manifest_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-worm-manifest",
            "--worm-manifest",
            str(manifest_path),
            "--proof-bundle",
            str(bundle_path),
            "--timestamp-anchor",
            str(anchor_path),
            "--rfc3161-request",
            str(rfc3161_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
