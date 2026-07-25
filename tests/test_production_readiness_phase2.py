from __future__ import annotations

import copy

import pytest

from governance.production_readiness_phase2 import (
    BLOCKED,
    PHASE2_APPROVAL_SCHEMA,
    PHASE2_POLICY_VERSION,
    READY,
    REVIEW_REQUIRED,
    deterministic_release_approval_hash,
    evaluate_phase2_readiness,
    export_phase2_evidence,
    load_phase2_manifest,
)


TIMESTAMP = "2026-07-25T00:00:00Z"
APPROVAL_EXPIRY = "2026-07-26T00:00:00Z"
COMMIT_SHA = "a" * 40


@pytest.fixture
def manifest() -> dict:
    return copy.deepcopy(load_phase2_manifest())


def _approval(readiness_id: str, evaluation_id: str, *, expires_at: str = APPROVAL_EXPIRY) -> dict:
    payload = {
        "schema": PHASE2_APPROVAL_SCHEMA,
        "approval_state": "APPROVED",
        "commit_sha": COMMIT_SHA,
        "readiness_id": readiness_id,
        "readiness_evaluation_id": evaluation_id,
        "policy_version": PHASE2_POLICY_VERSION,
        "issued_at": TIMESTAMP,
        "expires_at": expires_at,
    }
    return {**payload, "approval_hash": deterministic_release_approval_hash(payload)}


def _preapproval_ids(manifest: dict) -> tuple[str, str]:
    pending = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)
    return pending.readiness_id, pending.evaluation_id


def test_ready_controls_without_approval_require_review(manifest: dict) -> None:
    result = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == REVIEW_REQUIRED
    assert result.approval_state == "MISSING"
    assert result.blocker_list == ("PR2_RELEASE_APPROVAL_MISSING",)
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False


def test_valid_approval_returns_ready_metadata(manifest: dict) -> None:
    readiness_id, evaluation_id = _preapproval_ids(manifest)
    approval = _approval(readiness_id, evaluation_id)

    result = evaluate_phase2_readiness(manifest, approval=approval, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == READY
    assert result.blocker_list == ()
    assert result.approval_state == "APPROVED"
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False


def test_missing_secret_blocks(manifest: dict) -> None:
    manifest["secrets_management"]["required_secrets"][0]["configured"] = False

    result = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_SECRET_MISSING:github_actions_oidc" in result.blocker_list


def test_forbidden_plaintext_secret_blocks(manifest: dict) -> None:
    manifest["secrets_management"]["required_secrets"][0]["value"] = "do-not-log"

    result = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_MANIFEST_RAW_SECRET_FIELD_PRESENT" in result.blocker_list
    assert "PR2_SECRET_PLAINTEXT_PRESENT:github_actions_oidc" in result.blocker_list


def test_placeholder_secret_blocks(manifest: dict) -> None:
    manifest["secrets_management"]["required_secrets"][0]["storage_ref"] = "CHANGE_ME"

    result = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_SECRET_PLACEHOLDER_PRESENT:github_actions_oidc" in result.blocker_list


def test_monitoring_domain_missing_blocks(manifest: dict) -> None:
    del manifest["monitoring_baseline"]["checks"]["audit_health"]

    result = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_MONITORING_DOMAIN_MISSING:audit_health" in result.blocker_list


def test_external_monitoring_provider_blocks(manifest: dict) -> None:
    manifest["monitoring_baseline"]["checks"]["runtime_health"]["external_provider"] = "vendor"

    result = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_MONITORING_EXTERNAL_PROVIDER_ENABLED:runtime_health" in result.blocker_list


def test_backup_execution_blocks(manifest: dict) -> None:
    manifest["backup_readiness"]["backup_execution"] = True

    result = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_BACKUP_EXECUTION_ENABLED" in result.blocker_list


def test_restore_policy_missing_blocks(manifest: dict) -> None:
    manifest["backup_readiness"]["restore_policy_ref"] = ""

    result = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_BACKUP_RESTORE_POLICY_REF_MISSING" in result.blocker_list


def test_disaster_recovery_checkpoint_missing_blocks(manifest: dict) -> None:
    manifest["disaster_recovery"]["recovery_checkpoints"] = []

    result = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_DR_RECOVERY_CHECKPOINTS_INVALID" in result.blocker_list


def test_runbook_missing_blocks(manifest: dict) -> None:
    del manifest["operational_runbooks"]["runbooks"]["rollback"]

    result = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_RUNBOOK_MISSING:rollback" in result.blocker_list


def test_expired_approval_blocks(manifest: dict) -> None:
    readiness_id, evaluation_id = _preapproval_ids(manifest)
    approval = _approval(readiness_id, evaluation_id, expires_at="2026-07-24T00:00:00Z")

    result = evaluate_phase2_readiness(manifest, approval=approval, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_RELEASE_APPROVAL_EXPIRED" in result.blocker_list


def test_commit_bound_approval_mismatch_blocks(manifest: dict) -> None:
    readiness_id, evaluation_id = _preapproval_ids(manifest)
    approval = _approval(readiness_id, evaluation_id)

    result = evaluate_phase2_readiness(manifest, approval=approval, commit_sha="b" * 40, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_RELEASE_APPROVAL_COMMIT_SHA_MISMATCH" in result.blocker_list


def test_approval_hash_mismatch_blocks(manifest: dict) -> None:
    readiness_id, evaluation_id = _preapproval_ids(manifest)
    approval = _approval(readiness_id, evaluation_id)
    approval["approval_hash"] = "sha256:" + "0" * 64

    result = evaluate_phase2_readiness(manifest, approval=approval, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert "PR2_RELEASE_APPROVAL_HASH_INVALID" in result.blocker_list


def test_evidence_export_is_deterministic_and_redacted(manifest: dict) -> None:
    readiness_id, evaluation_id = _preapproval_ids(manifest)
    approval = _approval(readiness_id, evaluation_id)
    result = evaluate_phase2_readiness(manifest, approval=approval, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    first = export_phase2_evidence(result)
    second = export_phase2_evidence(result)

    assert first == second
    assert first["schema"] == "usbay.production_readiness.phase2.evidence_export.v1"
    assert first["release_gate_result"] == READY
    assert first["evidence_export_hash"].startswith("sha256:")
    rendered = str(first)
    assert "do-not-log" not in rendered
    assert "private_key" not in rendered
    assert first["execution_allowed"] is False
    assert first["provider_execution"] is False
    assert first["production_activation"] is False


def test_deterministic_blocker_ordering(manifest: dict) -> None:
    manifest["backup_readiness"]["backup_execution"] = True
    manifest["monitoring_baseline"]["checks"]["runtime_health"]["status"] = BLOCKED

    first = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)
    second = evaluate_phase2_readiness(manifest, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert first.blocker_list == second.blocker_list
    assert first.blocker_list == tuple(sorted(first.blocker_list))


def test_malformed_manifest_fails_closed() -> None:
    result = evaluate_phase2_readiness(None, commit_sha=COMMIT_SHA, timestamp=TIMESTAMP)

    assert result.release_gate_result == BLOCKED
    assert result.blocker_list == ("PR2_MANIFEST_MISSING",)
