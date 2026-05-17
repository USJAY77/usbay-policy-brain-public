from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.runtime_parity import (
    PARITY_DEGRADED,
    PARITY_DENY,
    PARITY_FAIL_CLOSED,
    PARITY_HUMAN_REVIEW,
    PARITY_MATCH,
    RUNTIME_PARITY_ERROR_CODES,
    RuntimeParityError,
    assert_runtime_parity_safe,
    explain_runtime_parity_failure,
    load_runtime_parity_error_registry,
    runtime_attestation_metadata,
    verify_runtime_parity,
)


ROOT = Path(__file__).resolve().parents[1]


def _runtime_state(**overrides: str) -> dict[str, str]:
    state = {
        "commit_hash": "a" * 64,
        "policy_hash": "b" * 64,
        "manifest_hash": "c" * 64,
        "evidence_hash": "d" * 64,
        "build_artifact_signature_hash": "e" * 64,
        "build_timestamp": "2026-05-17T00:00:00Z",
        "runtime_environment": "replit-production",
        "deployment_source": "github_main",
    }
    state.update(overrides)
    return state


def _canonical_state(**overrides) -> dict:
    state = {
        "github_main_head": "a" * 64,
        "approved_governance_branch_heads": {"governance/runtime-parity": "f" * 64},
        "approved_deployment_sources": ["github_main", "governance/runtime-parity"],
        "allowed_stale_commits": [],
        "expected_policy_hash": "b" * 64,
        "expected_manifest_hash": "c" * 64,
        "expected_evidence_hash": "d" * 64,
        "expected_build_artifact_signature_hash": "e" * 64,
    }
    state.update(overrides)
    return state


def test_matching_runtime_parity_passes() -> None:
    result = verify_runtime_parity(_runtime_state(), _canonical_state())

    assert result.valid is True
    assert result.parity_status == PARITY_MATCH
    assert result.reason_code == "RUNTIME_PARITY_MATCH"
    assert runtime_attestation_metadata(result)["commit_hash"] == "a" * 64


def test_stale_commit_hash_degrades_when_explicitly_allowed() -> None:
    result = verify_runtime_parity(
        _runtime_state(commit_hash="9" * 64),
        _canonical_state(allowed_stale_commits=["9" * 64]),
    )

    assert result.valid is False
    assert result.parity_status == PARITY_DEGRADED
    assert result.reason_code == "RUNTIME_PARITY_STALE_COMMIT"


def test_mismatched_policy_hash_denies() -> None:
    result = verify_runtime_parity(_runtime_state(policy_hash="0" * 64), _canonical_state())

    assert result.parity_status == PARITY_DENY
    assert "RUNTIME_PARITY_POLICY_HASH_MISMATCH" in result.errors


def test_missing_evidence_manifest_fails_closed() -> None:
    result = verify_runtime_parity(_runtime_state(evidence_hash=""), _canonical_state())

    assert result.parity_status == PARITY_FAIL_CLOSED
    assert "RUNTIME_PARITY_EVIDENCE_MANIFEST_MISSING" in result.errors


def test_unknown_runtime_source_requires_human_review() -> None:
    result = verify_runtime_parity(_runtime_state(deployment_source="unknown-runtime"), _canonical_state())

    assert result.parity_status == PARITY_HUMAN_REVIEW
    assert "RUNTIME_PARITY_UNKNOWN_SOURCE" in result.errors


def test_build_artifact_signature_mismatch_denies() -> None:
    result = verify_runtime_parity(_runtime_state(build_artifact_signature_hash="1" * 64), _canonical_state())

    assert result.parity_status == PARITY_DENY
    assert "RUNTIME_PARITY_ARTIFACT_SIGNATURE_MISMATCH" in result.errors


def test_no_secret_leakage_in_parity_output() -> None:
    result = verify_runtime_parity(_runtime_state(), _canonical_state())
    output = json.dumps(runtime_attestation_metadata(result), sort_keys=True)

    assert "PRIVATE KEY" not in output
    assert "approval_contents" not in output
    assert "secret" not in output.lower()
    assert "token" not in output.lower()


def test_fail_closed_on_verifier_unsafe_payload() -> None:
    result = verify_runtime_parity({**_runtime_state(), "private_key": "do-not-log"}, _canonical_state())

    assert result.parity_status == PARITY_FAIL_CLOSED
    assert "RUNTIME_PARITY_DIAGNOSTICS_UNSAFE" in result.errors


def test_runtime_parity_error_registry_complete() -> None:
    registry = load_runtime_parity_error_registry(ROOT)

    assert set(RUNTIME_PARITY_ERROR_CODES).issubset(registry)
    assert explain_runtime_parity_failure(ROOT, "RUNTIME_PARITY_POLICY_HASH_MISMATCH")["fail_closed_reason"]


def test_assert_runtime_parity_safe_rejects_sensitive_output() -> None:
    try:
        assert_runtime_parity_safe({"diagnostics": {"approval_contents": "do-not-log"}})
    except RuntimeParityError as exc:
        assert str(exc) == "RUNTIME_PARITY_DIAGNOSTICS_UNSAFE"
    else:
        raise AssertionError("unsafe runtime parity diagnostics were accepted")


def test_runtime_parity_cli_outputs_safe_metadata_and_evidence(tmp_path: Path) -> None:
    runtime_path = tmp_path / "runtime.json"
    canonical_path = tmp_path / "canonical.json"
    evidence_path = tmp_path / "runtime-parity-evidence.jsonl"
    runtime_path.write_text(json.dumps(_runtime_state(), sort_keys=True), encoding="utf-8")
    canonical_path.write_text(json.dumps(_canonical_state(), sort_keys=True), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-runtime-parity",
            "--runtime-state",
            str(runtime_path),
            "--canonical-state",
            str(canonical_path),
            "--parity-evidence-output",
            str(evidence_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    assert '"parity_status":"MATCH"' in completed.stdout
    assert evidence_path.is_file()
    assert "PRIVATE KEY" not in completed.stdout
    assert "approval_contents" not in completed.stdout
    assert "PRIVATE KEY" not in evidence_path.read_text(encoding="utf-8")
