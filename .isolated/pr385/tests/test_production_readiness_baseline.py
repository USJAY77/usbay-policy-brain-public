from __future__ import annotations

import copy

import pytest

from governance.hashing import sha256_reference
from governance.production_readiness_baseline import (
    BLOCKED,
    HUMAN_APPROVAL_SCHEMA,
    MANDATORY_CONTROL_IDS,
    PHASE1_POLICY_VERSION,
    READY,
    evaluate_readiness_manifest,
    evaluate_release_readiness,
    export_readiness_evidence,
    load_readiness_manifest,
)


TIMESTAMP = "2026-07-25T00:00:00Z"
APPROVAL_EXPIRY = "2026-07-26T00:00:00Z"
COMMIT_SHA = "a" * 40


@pytest.fixture
def manifest() -> dict:
    return copy.deepcopy(load_readiness_manifest())


def _approval(evaluation_id: str, *, commit_sha: str = COMMIT_SHA, expires_at: str = APPROVAL_EXPIRY) -> dict:
    payload = {
        "schema": HUMAN_APPROVAL_SCHEMA,
        "approval_state": "APPROVED",
        "commit_sha": commit_sha,
        "readiness_evaluation_id": evaluation_id,
        "policy_version": PHASE1_POLICY_VERSION,
        "expires_at": expires_at,
        "approved_by": "human-governance-review",
    }
    return {**payload, "approval_hash": sha256_reference(payload)}


def test_all_controls_pass_but_missing_human_approval_blocks_release(manifest: dict) -> None:
    decision = evaluate_release_readiness(manifest, commit_sha=COMMIT_SHA, evaluation_timestamp=TIMESTAMP)

    assert decision.readiness_state == BLOCKED
    assert decision.human_approval_state == "MISSING"
    assert decision.failed_control_ids == ()
    assert "PR_HUMAN_RELEASE_APPROVAL_MISSING" in decision.reason_codes
    assert decision.execution_allowed is False
    assert decision.provider_execution is False
    assert decision.production_activation is False


def test_missing_required_control_blocks(manifest: dict) -> None:
    manifest["controls"] = [control for control in manifest["controls"] if control["control_id"] != "PR-003"]

    evaluation = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)

    assert evaluation.readiness_state == BLOCKED
    assert "PR-003" in evaluation.failed_control_ids
    assert "PR_REQUIRED_CONTROL_MISSING:PR-003" in evaluation.reason_codes


def test_missing_evidence_blocks(manifest: dict) -> None:
    manifest["controls"][0]["evidence_references"] = ["missing/evidence.json"]

    evaluation = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)

    assert evaluation.readiness_state == BLOCKED
    assert "PR-001" in evaluation.failed_control_ids
    assert "PR_CONTROL_EVIDENCE_MISSING:PR-001:missing/evidence.json" in evaluation.reason_codes


def test_invalid_manifest_blocks(manifest: dict) -> None:
    manifest["schema"] = "wrong"

    evaluation = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)

    assert evaluation.readiness_state == BLOCKED
    assert "PR_MANIFEST_SCHEMA_INVALID" in evaluation.reason_codes


def test_high_blocker_blocks(manifest: dict) -> None:
    manifest["controls"][2]["risk_level"] = "HIGH"
    manifest["controls"][2]["blocker_status"] = True

    evaluation = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)

    assert evaluation.readiness_state == BLOCKED
    assert "PR-003" in evaluation.failed_control_ids
    assert "PR_CONTROL_HIGH_BLOCKER_PRESENT:PR-003" in evaluation.reason_codes


def test_stale_approval_blocks(manifest: dict) -> None:
    evaluation = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)
    approval = _approval(evaluation.evaluation_id, expires_at="2026-07-24T00:00:00Z")

    decision = evaluate_release_readiness(
        manifest,
        approval=approval,
        commit_sha=COMMIT_SHA,
        evaluation_timestamp=TIMESTAMP,
    )

    assert decision.readiness_state == BLOCKED
    assert "PR_HUMAN_RELEASE_APPROVAL_EXPIRED" in decision.reason_codes


def test_mismatched_commit_sha_blocks(manifest: dict) -> None:
    evaluation = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)
    approval = _approval(evaluation.evaluation_id, commit_sha="b" * 40)

    decision = evaluate_release_readiness(
        manifest,
        approval=approval,
        commit_sha=COMMIT_SHA,
        evaluation_timestamp=TIMESTAMP,
    )

    assert decision.readiness_state == BLOCKED
    assert "PR_HUMAN_RELEASE_APPROVAL_COMMIT_SHA_MISMATCH" in decision.reason_codes


def test_exact_valid_human_approval_allows_ready_metadata(manifest: dict) -> None:
    evaluation = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)
    approval = _approval(evaluation.evaluation_id)

    decision = evaluate_release_readiness(
        manifest,
        approval=approval,
        commit_sha=COMMIT_SHA,
        evaluation_timestamp=TIMESTAMP,
    )

    assert decision.readiness_state == READY
    assert decision.human_approval_state == "APPROVED"
    assert decision.reason_codes == ()
    assert decision.execution_allowed is False
    assert decision.provider_execution is False
    assert decision.production_activation is False


def test_evaluator_exception_fails_closed(monkeypatch, manifest: dict) -> None:
    import governance.production_readiness_baseline as baseline

    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(baseline, "_evaluate_control", explode)

    evaluation = baseline.evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)

    assert evaluation.readiness_state == BLOCKED
    assert evaluation.reason_codes == ("PR_EVALUATOR_EXCEPTION",)


def test_deterministic_evidence_export(manifest: dict) -> None:
    evaluation = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)
    approval = _approval(evaluation.evaluation_id)
    decision = evaluate_release_readiness(
        manifest,
        approval=approval,
        commit_sha=COMMIT_SHA,
        evaluation_timestamp=TIMESTAMP,
    )

    first = export_readiness_evidence(decision, evaluation.control_results)
    second = export_readiness_evidence(decision, evaluation.control_results)

    assert first == second
    assert first["schema"] == "usbay.production_readiness.phase1.evidence_export.v1"
    assert first["overall_readiness_state"] == READY
    assert first["evidence_export_hash"].startswith("sha256:")
    assert first["execution_allowed"] is False
    assert first["provider_execution"] is False
    assert first["production_activation"] is False


def test_reason_codes_are_stable(manifest: dict) -> None:
    manifest["controls"][1]["readiness_outcome"] = BLOCKED
    manifest["controls"][0]["readiness_outcome"] = BLOCKED

    first = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)
    second = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)

    assert first.reason_codes == second.reason_codes
    assert first.reason_codes == tuple(sorted(first.reason_codes))


def test_no_production_activation_in_manifest_or_decision(manifest: dict) -> None:
    evaluation = evaluate_readiness_manifest(manifest, evaluation_timestamp=TIMESTAMP)
    approval = _approval(evaluation.evaluation_id)
    decision = evaluate_release_readiness(
        manifest,
        approval=approval,
        commit_sha=COMMIT_SHA,
        evaluation_timestamp=TIMESTAMP,
    )

    assert tuple(control["control_id"] for control in manifest["controls"]) == MANDATORY_CONTROL_IDS
    assert decision.production_activation is False
    assert decision.provider_execution is False
    assert decision.execution_allowed is False
