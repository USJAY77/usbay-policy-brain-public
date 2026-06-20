from __future__ import annotations

import hashlib

import pytest

from governance.runtime_parity import (
    PARITY_DEGRADED,
    PARITY_FAIL_CLOSED,
    ATTESTATION_UNTRUSTED,
    canonical_governance_state_hash,
    create_runtime_manifest,
    verify_runtime_attestation_parity,
    verify_runtime_parity,
)
from governance.runtime_parity_validator import (
    REASON_RUNTIME_EVALUATION_BLOCKED,
    runtime_validation_report,
    validate_runtime_parity,
)


pytestmark = pytest.mark.governance


def test_runtime_parity_validator_passes_for_canonical_read_only_state():
    report = validate_runtime_parity()
    validation = runtime_validation_report()

    assert report["runtime_parity_status"] == "VALID"
    assert report["blocked_checks"] == []
    assert report["read_only"] is True
    assert report["execution_enabled"] is False
    assert report["deployment_enabled"] is False
    assert report["runtime_modification_enabled"] is False
    assert report["policy_mutation_enabled"] is False
    assert report["connector_write_enabled"] is False
    assert report["auto_remediation_enabled"] is False
    assert report["auto_approval_enabled"] is False
    assert validation["runtime_validation_status"] == "VALID"
    assert validation["runtime_validation_score"] == 100


def test_runtime_parity_validator_fails_closed_for_blocked_runtime_evaluation():
    report = validate_runtime_parity(runtime_evaluation={"runtime_evaluation_status": "BLOCKED"})
    validation = runtime_validation_report(runtime_evaluation={"runtime_evaluation_status": "BLOCKED"})

    assert report["runtime_parity_status"] == "BLOCKED"
    assert "runtime_evaluation" in report["blocked_checks"]
    assert REASON_RUNTIME_EVALUATION_BLOCKED in report["reason_codes"]
    assert validation["runtime_validation_status"] == "BLOCKED"
    assert "runtime_parity" in validation["blockers"]


def test_runtime_parity_validator_fails_closed_for_duplicate_status(monkeypatch):
    from governance import runtime_parity_validator as validator

    def duplicate_block():
        return {
            "duplicate_status": "BLOCKED",
            "duplicate_owner_count": 1,
            "duplicate_dashboard_owner_count": 0,
            "duplicate_reason_code_owner_count": 0,
            "duplicate_audit_owner_count": 0,
            "duplicate_evidence_owner_count": 0,
            "duplicate_lineage_owner_count": 0,
            "reason_codes": ["DUPLICATE_OWNER"],
        }

    monkeypatch.setattr(validator, "detect_governance_duplicates", duplicate_block)

    report = validate_runtime_parity()
    validation = runtime_validation_report()

    assert report["runtime_parity_status"] == "BLOCKED"
    assert "duplicate_registry" in report["blocked_checks"]
    assert validation["runtime_validation_status"] == "BLOCKED"
    assert "runtime_parity" in validation["blockers"]


def _canonical_state() -> dict:
    return {
        "policy_version_hash": "a" * 64,
        "commit_sha": "b" * 64,
        "provenance_fingerprint": "c" * 64,
        "approved_deployment_sources": ["github_main"],
        "github_main_head": "b" * 64,
        "expected_policy_hash": "a" * 64,
        "expected_manifest_hash": "d" * 64,
        "expected_evidence_hash": "e" * 64,
        "expected_build_artifact_signature_hash": "f" * 64,
    }


def test_runtime_manifest_corruption_fails_closed() -> None:
    canonical = _canonical_state()
    manifest = create_runtime_manifest(
        runtime_id="runtime-1",
        runtime_version="1.0",
        commit_sha=canonical["commit_sha"],
        policy_hash=canonical["policy_version_hash"],
        provenance_fingerprint=canonical["provenance_fingerprint"],
        deployment_mode="production",
        generated_at_utc="2026-06-20T00:00:00Z",
        canonical_governance_state_hash=canonical_governance_state_hash(canonical),
    )
    manifest["canonical_governance_state_hash"] = "0" * 64

    result = verify_runtime_attestation_parity(manifest, canonical)

    assert result.valid is False
    assert result.parity_status == ATTESTATION_UNTRUSTED
    assert "RUNTIME_PARITY_MISMATCH" in result.reason_codes
    assert result.fail_closed is True


def test_runtime_provenance_corruption_fails_closed() -> None:
    canonical = _canonical_state()
    manifest = create_runtime_manifest(
        runtime_id="runtime-1",
        runtime_version="1.0",
        commit_sha=canonical["commit_sha"],
        policy_hash=canonical["policy_version_hash"],
        provenance_fingerprint="0" * 64,
        deployment_mode="production",
        generated_at_utc="2026-06-20T00:00:00Z",
        canonical_governance_state_hash=canonical_governance_state_hash(canonical),
    )

    result = verify_runtime_attestation_parity(manifest, canonical)

    assert result.valid is False
    assert result.parity_status == ATTESTATION_UNTRUSTED
    assert "RUNTIME_ATTESTATION_UNTRUSTED" in result.reason_codes
    assert result.fail_closed is True


def test_runtime_stale_hash_degrades_without_execution_match() -> None:
    canonical = _canonical_state()
    stale_commit = "1" * 64
    runtime_state = {
        "commit_hash": stale_commit,
        "policy_hash": canonical["expected_policy_hash"],
        "manifest_hash": canonical["expected_manifest_hash"],
        "evidence_hash": canonical["expected_evidence_hash"],
        "build_timestamp": "2026-06-20T00:00:00Z",
        "runtime_environment": "production",
        "deployment_source": "github_main",
        "build_artifact_signature_hash": canonical["expected_build_artifact_signature_hash"],
    }

    result = verify_runtime_parity(runtime_state, {**canonical, "allowed_stale_commits": [stale_commit]})

    assert result.valid is False
    assert result.parity_status == PARITY_DEGRADED
    assert result.reason_code == "RUNTIME_PARITY_STALE_COMMIT"
    assert "RUNTIME_PARITY_STALE_COMMIT" in result.errors


def test_runtime_evidence_manifest_hash_corruption_fails_closed() -> None:
    canonical = _canonical_state()
    runtime_state = {
        "commit_hash": canonical["github_main_head"],
        "policy_hash": canonical["expected_policy_hash"],
        "manifest_hash": canonical["expected_manifest_hash"],
        "evidence_hash": hashlib.sha256(b"corrupted-evidence").hexdigest(),
        "build_timestamp": "2026-06-20T00:00:00Z",
        "runtime_environment": "production",
        "deployment_source": "github_main",
        "build_artifact_signature_hash": canonical["expected_build_artifact_signature_hash"],
    }

    result = verify_runtime_parity(runtime_state, canonical)

    assert result.valid is False
    assert result.parity_status == PARITY_FAIL_CLOSED
    assert result.reason_code == "RUNTIME_PARITY_EVIDENCE_MANIFEST_MISSING"
