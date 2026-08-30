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
    rfc3161_timestamp_audit_evidence,
    timestamp_authority_map,
    timestamp_chain_readiness_report,
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


def _valid_timestamp_chain() -> dict:
    subject_paths = (
        ("evidence_package", "docs/governance/PB008_RFC3161_TIMESTAMP_CONTROL.md"),
        ("validation_result", "scripts/verify_timestamp_chain.py"),
        ("review_decision", "governance/timestamps/timestamp_relationships.md"),
        ("export_bundle", "governance/timestamps/timestamp_schema.json"),
        ("audit_lineage", "governance/timestamps/timestamp_example.json"),
    )
    current_hashes = ("a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64)
    records = []
    previous_hash = "GENESIS"
    for index, ((subject_type, subject_path), current_hash) in enumerate(zip(subject_paths, current_hashes), start=1):
        records.append(
            {
                "timestamp_record_id": f"timestamp-record-{index}",
                "timestamp_schema": "usbay.governance.rfc3161_timestamp_record.v1",
                "timestamp_subject_type": subject_type,
                "timestamp_subject_id": f"{subject_type}-subject",
                "timestamp_subject_path": subject_path,
                "timestamp_subject_sha256": str(index) * 64,
                "rfc3161_token_sha256": str(index + 1) * 64,
                "tsa_policy_id": "USBAY-RFC3161-CANONICAL-AUTHORITY",
                "tsa_certificate_sha256": str(index + 2) * 64,
                "timestamp_utc": f"2026-05-12T00:0{index}:00Z",
                "previous_timestamp_record_sha256": previous_hash,
                "timestamp_record_sha256": current_hash,
                "linked_audit_reference": f"audit-reference-{index}",
                "decision": "BLOCKED",
            }
        )
        previous_hash = current_hash
    return {
        "schema": "usbay.governance.rfc3161_timestamp_chain.v1",
        "chain_id": "canonical-rfc3161-test-chain",
        "decision": "BLOCKED",
        "blocker_status": {"BLOCKER-003": "OPEN"},
        "certification_status": "BLOCKED",
        "certification_claim": False,
        "runtime_behavior_change": False,
        "aws_resource_creation": False,
        "credentials_included": False,
        "timestamp_records": records,
        "relationships": {
            "evidence_package_to_validation_result": "timestamp-record-1 -> timestamp-record-2",
            "validation_result_to_review_decision": "timestamp-record-2 -> timestamp-record-3",
            "review_decision_to_export_bundle": "timestamp-record-3 -> timestamp-record-4",
            "export_bundle_to_audit_lineage": "timestamp-record-4 -> timestamp-record-5",
        },
    }


def _write_timestamp_chain(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def test_timestamp_authority_map_selects_single_owner() -> None:
    authority = timestamp_authority_map()

    assert authority["canonical_owner_module"] == "governance.rfc3161_timestamp"
    assert [entry for entry in authority["ownership"] if entry["role"] == "owner"] == [
        {
            "module": "governance.rfc3161_timestamp",
            "role": "owner",
            "surface": "canonical RFC3161 request validation and timestamp authority readiness",
        }
    ]
    assert authority["duplicate_ownership_paths"] == []
    assert authority["execution_enabled"] is False


def test_timestamp_chain_readiness_accepts_valid_fixture(tmp_path: Path) -> None:
    chain_path = tmp_path / "timestamp-chain.json"
    _write_timestamp_chain(chain_path, _valid_timestamp_chain())

    readiness = timestamp_chain_readiness_report(chain_path=chain_path)

    assert readiness["timestamp_authority_status"] == "VALID"
    assert readiness["timestamp_chain_status"] == "VALID"
    assert readiness["reason_codes"] == []


def test_missing_timestamp_chain_blocks_readiness(tmp_path: Path) -> None:
    readiness = timestamp_chain_readiness_report(chain_path=tmp_path / "missing-chain.json")

    assert readiness["timestamp_authority_status"] == "BLOCKED"
    assert "RFC3161_TIMESTAMP_CHAIN_INVALID" in readiness["reason_codes"]
    assert any(str(reason).startswith("TIMESTAMP_MISSING") for reason in readiness["reason_codes"])
    assert readiness["fail_closed"] is True


def test_invalid_timestamp_chain_blocks_readiness(tmp_path: Path) -> None:
    chain = _valid_timestamp_chain()
    chain["timestamp_records"][0]["timestamp_utc"] = "not-a-timestamp"
    chain_path = tmp_path / "invalid-chain.json"
    _write_timestamp_chain(chain_path, chain)

    readiness = timestamp_chain_readiness_report(chain_path=chain_path)

    assert readiness["timestamp_authority_status"] == "BLOCKED"
    assert "TIMESTAMP_INVALID:record_0:timestamp_utc" in readiness["reason_codes"]


def test_broken_timestamp_continuity_blocks_readiness(tmp_path: Path) -> None:
    chain = _valid_timestamp_chain()
    chain["timestamp_records"][1]["previous_timestamp_record_sha256"] = "0" * 64
    chain_path = tmp_path / "broken-continuity-chain.json"
    _write_timestamp_chain(chain_path, chain)

    evidence = rfc3161_timestamp_audit_evidence(chain_path=chain_path)

    assert evidence["timestamp_authority_status"] == "BLOCKED"
    assert "TIMESTAMP_CHAIN_INCOMPLETE:record_1:previous_hash_mismatch" in evidence["readiness"]["reason_codes"]


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
