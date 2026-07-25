from __future__ import annotations

import copy
from pathlib import Path

import pytest

from governance.production_readiness_phase3 import (
    APPROVED,
    BLOCKED,
    PHASE3_APPROVAL_SCHEMA,
    PHASE3_POLICY_VERSION,
    READY,
    deterministic_phase3_approval_hash,
    deterministic_persistence_hash,
    evaluate_phase3_readiness,
    export_phase3_evidence,
    load_phase3_manifest,
    load_phase3_manifest_safely,
)


TIMESTAMP = "2026-07-25T00:00:00Z"
EXPIRY = "2026-07-26T00:00:00Z"
COMMIT_SHA = "a" * 40
BRANCH = "usbay/production-readiness-phase-3-operational-resilience"


@pytest.fixture
def manifest() -> dict:
    payload = copy.deepcopy(load_phase3_manifest())
    record = payload["controls"][-1]["persistence_record"]
    record["persistence_hash"] = deterministic_persistence_hash(record)
    return payload


def _approve(manifest: dict, *, commit_sha: str = COMMIT_SHA, branch: str = BRANCH, expiry: str = EXPIRY) -> dict:
    pending = evaluate_phase3_readiness(manifest, commit_sha=commit_sha, branch=branch, timestamp=TIMESTAMP)
    payload = {
        "schema": PHASE3_APPROVAL_SCHEMA,
        "commit_sha": commit_sha,
        "branch": branch,
        "release_identifier": "phase3-release-readiness",
        "production_readiness_evaluation_id": pending.evaluation_id,
        "policy_version": PHASE3_POLICY_VERSION,
        "control_manifest_version": manifest["manifest_version"],
        "evidence_export_hash": "sha256:" + "5" * 64,
        "approval_actor": "human-governance-review",
        "approval_role": "release-approver",
        "approval_timestamp": TIMESTAMP,
        "approval_expiry": expiry,
        "approval_decision": APPROVED,
    }
    return {**payload, "approval_hash": deterministic_phase3_approval_hash(payload)}


def _ready(manifest: dict):
    return evaluate_phase3_readiness(
        manifest,
        approval=_approve(manifest),
        commit_sha=COMMIT_SHA,
        branch=BRANCH,
        timestamp=TIMESTAMP,
    )


def _control(manifest: dict, control_id: str) -> dict:
    return next(control for control in manifest["controls"] if control["control_id"] == control_id)


def _assert_blocked(manifest: dict, reason: str) -> None:
    result = _ready(manifest)
    assert result.readiness_outcome == BLOCKED
    assert reason in result.blockers
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.release_authorized is False


def test_valid_complete_manifest_returns_ready(manifest: dict) -> None:
    result = _ready(manifest)

    assert result.readiness_outcome == READY
    assert result.blockers == ()
    assert result.approval_state == APPROVED
    assert result.release_state == "NOT_AUTHORIZED"


def test_missing_manifest_blocks() -> None:
    result = evaluate_phase3_readiness(None, commit_sha=COMMIT_SHA, branch=BRANCH, timestamp=TIMESTAMP)

    assert result.readiness_outcome == BLOCKED
    assert result.blockers == ("PR3_MANIFEST_MISSING",)


def test_invalid_json_loads_as_missing_and_blocks(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text("{not-json", encoding="utf-8")

    result = evaluate_phase3_readiness(load_phase3_manifest_safely(path), commit_sha=COMMIT_SHA, branch=BRANCH, timestamp=TIMESTAMP)

    assert result.readiness_outcome == BLOCKED
    assert result.blockers == ("PR3_MANIFEST_MISSING",)


def test_invalid_schema_blocks(manifest: dict) -> None:
    manifest["schema"] = "wrong"

    _assert_blocked(manifest, "PR3_MANIFEST_SCHEMA_INVALID")


def test_missing_control_blocks(manifest: dict) -> None:
    manifest["controls"] = [control for control in manifest["controls"] if control["control_id"] != "backup_governance"]

    _assert_blocked(manifest, "PR3_CONTROL_MISSING:backup_governance")


def test_duplicate_control_blocks(manifest: dict) -> None:
    manifest["controls"].append(copy.deepcopy(manifest["controls"][0]))

    _assert_blocked(manifest, "PR3_CONTROL_DUPLICATE:secrets_credential_governance")


def test_unknown_control_blocks(manifest: dict) -> None:
    manifest["controls"][0]["control_id"] = "unknown_control"

    _assert_blocked(manifest, "PR3_CONTROL_UNKNOWN:unknown_control")


def test_missing_evidence_blocks(manifest: dict) -> None:
    _control(manifest, "backup_governance")["evidence_references"] = ["missing/evidence.md"]

    _assert_blocked(manifest, "PR3_EVIDENCE_REFERENCE_MISSING:backup_governance:missing/evidence.md")


def test_invalid_evidence_hash_blocks(manifest: dict) -> None:
    control = _control(manifest, "backup_governance")
    control["evidence_hashes"] = {
        "docs/governance/PRODUCTION_READINESS_PHASE_3_OPERATIONAL_RESILIENCE.md": "sha256:" + "0" * 64
    }

    _assert_blocked(
        manifest,
        "PR3_EVIDENCE_HASH_MISMATCH:backup_governance:docs/governance/PRODUCTION_READINESS_PHASE_3_OPERATIONAL_RESILIENCE.md",
    )


def test_stale_evidence_blocks(manifest: dict) -> None:
    _control(manifest, "backup_governance")["evidence_timestamp"] = "2026-01-01T00:00:00Z"

    _assert_blocked(manifest, "PR3_EVIDENCE_STALE:backup_governance")


def test_critical_blocker_blocks(manifest: dict) -> None:
    control = _control(manifest, "backup_governance")
    control["risk"] = "CRITICAL"
    control["blocker_status"] = True

    _assert_blocked(manifest, "PR3_CONTROL_HIGH_RISK_BLOCKER:backup_governance")


def test_high_risk_blocker_blocks(manifest: dict) -> None:
    control = _control(manifest, "backup_governance")
    control["risk"] = "HIGH"
    control["blocker_status"] = True

    _assert_blocked(manifest, "PR3_CONTROL_HIGH_RISK_BLOCKER:backup_governance")


def test_missing_human_approval_blocks(manifest: dict) -> None:
    result = evaluate_phase3_readiness(manifest, commit_sha=COMMIT_SHA, branch=BRANCH, timestamp=TIMESTAMP)

    assert result.readiness_outcome == BLOCKED
    assert "PR3_RELEASE_APPROVAL_MISSING" in result.blockers


def test_expired_approval_blocks(manifest: dict) -> None:
    approval = _approve(manifest, expiry="2026-07-24T00:00:00Z")

    result = evaluate_phase3_readiness(manifest, approval=approval, commit_sha=COMMIT_SHA, branch=BRANCH, timestamp=TIMESTAMP)

    assert result.readiness_outcome == BLOCKED
    assert "PR3_RELEASE_APPROVAL_EXPIRED" in result.blockers


def test_approval_commit_mismatch_blocks(manifest: dict) -> None:
    approval = _approve(manifest)

    result = evaluate_phase3_readiness(manifest, approval=approval, commit_sha="b" * 40, branch=BRANCH, timestamp=TIMESTAMP)

    assert result.readiness_outcome == BLOCKED
    assert "PR3_RELEASE_APPROVAL_COMMIT_SHA_MISMATCH" in result.blockers


def test_approval_evaluation_mismatch_blocks(manifest: dict) -> None:
    approval = _approve(manifest)
    approval["production_readiness_evaluation_id"] = "sha256:" + "9" * 64
    approval["approval_hash"] = deterministic_phase3_approval_hash(approval)

    result = evaluate_phase3_readiness(manifest, approval=approval, commit_sha=COMMIT_SHA, branch=BRANCH, timestamp=TIMESTAMP)

    assert result.readiness_outcome == BLOCKED
    assert "PR3_RELEASE_APPROVAL_PRODUCTION_READINESS_EVALUATION_ID_MISMATCH" in result.blockers


def test_approval_hash_mismatch_blocks(manifest: dict) -> None:
    approval = _approve(manifest)
    approval["approval_hash"] = "sha256:" + "0" * 64

    result = evaluate_phase3_readiness(manifest, approval=approval, commit_sha=COMMIT_SHA, branch=BRANCH, timestamp=TIMESTAMP)

    assert result.readiness_outcome == BLOCKED
    assert "PR3_RELEASE_APPROVAL_HASH_INVALID" in result.blockers


def test_missing_secrets_owner_blocks(manifest: dict) -> None:
    _control(manifest, "secrets_credential_governance")["credentials"][0]["owner"] = ""

    _assert_blocked(manifest, "PR3_SECRET_OWNER_MISSING:github_actions_oidc")


def test_stale_credential_rotation_blocks(manifest: dict) -> None:
    _control(manifest, "secrets_credential_governance")["credentials"][0]["rotation_evidence_timestamp"] = "2026-01-01T00:00:00Z"

    _assert_blocked(manifest, "PR3_SECRET_ROTATION_STALE:github_actions_oidc")


def test_plaintext_secret_indicator_blocks(manifest: dict) -> None:
    _control(manifest, "secrets_credential_governance")["credentials"][0]["plaintext_detected"] = True

    _assert_blocked(manifest, "PR3_SECRET_UNSAFE_REPOSITORY_STATE:github_actions_oidc")


def test_repository_secret_indicator_blocks(manifest: dict) -> None:
    _control(manifest, "secrets_credential_governance")["credentials"][0]["repository_secret_detected"] = True

    _assert_blocked(manifest, "PR3_SECRET_UNSAFE_REPOSITORY_STATE:github_actions_oidc")


def test_missing_monitoring_coverage_blocks(manifest: dict) -> None:
    del _control(manifest, "monitoring_alerting_governance")["alerts"]["release_gate"]

    _assert_blocked(manifest, "PR3_MONITORING_SIGNAL_MISSING:release_gate")


def test_unacknowledged_critical_alert_blocks(manifest: dict) -> None:
    _control(manifest, "monitoring_alerting_governance")["alerts"]["release_gate"]["acknowledged"] = False

    _assert_blocked(manifest, "PR3_MONITORING_CRITICAL_UNACKNOWLEDGED:release_gate")


def test_missing_backup_evidence_blocks(manifest: dict) -> None:
    _control(manifest, "backup_governance")["integrity_hash_ref"] = ""

    _assert_blocked(manifest, "PR3_BACKUP_INTEGRITY_HASH_REF_MISSING")


def test_stale_backup_evidence_blocks(manifest: dict) -> None:
    _control(manifest, "backup_governance")["last_successful_backup_timestamp"] = "2026-07-23T00:00:00Z"

    _assert_blocked(manifest, "PR3_BACKUP_EVIDENCE_STALE")


def test_missing_restore_test_blocks(manifest: dict) -> None:
    _control(manifest, "restore_validation")["restore_test_ref"] = ""

    _assert_blocked(manifest, "PR3_RESTORE_TEST_MISSING")


def test_failed_restore_integrity_blocks(manifest: dict) -> None:
    _control(manifest, "restore_validation")["data_integrity_result"] = "FAIL"

    _assert_blocked(manifest, "PR3_RESTORE_DATA_INTEGRITY_FAILED")


def test_invalid_rto_rpo_blocks(manifest: dict) -> None:
    dr = _control(manifest, "disaster_recovery_governance")
    dr["rto"] = "zero"

    _assert_blocked(manifest, "PR3_DR_RTO_RPO_INVALID")


def test_missing_dr_authority_blocks(manifest: dict) -> None:
    _control(manifest, "disaster_recovery_governance")["human_command_authority"] = ""

    _assert_blocked(manifest, "PR3_DR_HUMAN_COMMAND_AUTHORITY_MISSING")


def test_failed_dr_exercise_blocks(manifest: dict) -> None:
    _control(manifest, "disaster_recovery_governance")["exercise_outcome"] = "FAIL"

    _assert_blocked(manifest, "PR3_DR_EXERCISE_FAILED")


def test_open_critical_incident_blocks(manifest: dict) -> None:
    incident = _control(manifest, "incident_response_governance")
    incident["severity"] = "CRITICAL"
    incident["closure_approval"] = "PENDING"

    _assert_blocked(manifest, "PR3_INCIDENT_CLOSURE_APPROVAL_MISSING")


def test_governance_integrity_incident_blocks(manifest: dict) -> None:
    _control(manifest, "incident_response_governance")["governance_integrity_affected"] = True

    _assert_blocked(manifest, "PR3_INCIDENT_GOVERNANCE_INTEGRITY_BLOCKED")


def test_missing_incident_closure_approval_blocks(manifest: dict) -> None:
    incident = _control(manifest, "incident_response_governance")
    incident["severity"] = "CRITICAL"
    incident["closure_approval"] = ""

    _assert_blocked(manifest, "PR3_INCIDENT_CLOSURE_APPROVAL_MISSING")


def test_missing_runbook_approval_blocks(manifest: dict) -> None:
    runbooks = _control(manifest, "operational_runbooks")["runbooks"]
    runbooks["rollback"]["required_human_approval"] = False

    _assert_blocked(manifest, "PR3_RUNBOOK_APPROVAL_MISSING:rollback")


def test_invalid_runbook_version_blocks(manifest: dict) -> None:
    runbooks = _control(manifest, "operational_runbooks")["runbooks"]
    runbooks["rollback"]["version"] = "1"

    _assert_blocked(manifest, "PR3_RUNBOOK_VERSION_INVALID:rollback")


def test_missing_rollback_step_blocks(manifest: dict) -> None:
    runbooks = _control(manifest, "operational_runbooks")["runbooks"]
    runbooks["rollback"]["rollback_step"] = ""

    _assert_blocked(manifest, "PR3_RUNBOOK_FIELD_MISSING:rollback:rollback_step")


def test_high_risk_change_without_approval_blocks(manifest: dict) -> None:
    change = _control(manifest, "change_management_governance")["changes"][0]
    change["risk_classification"] = "HIGH"
    change["approval_state"] = "PENDING"

    _assert_blocked(manifest, "PR3_CHANGE_HIGH_RISK_APPROVAL_MISSING:chg-phase3-001")


def test_change_without_rollback_evidence_blocks(manifest: dict) -> None:
    _control(manifest, "change_management_governance")["changes"][0]["rollback_reference"] = ""

    _assert_blocked(manifest, "PR3_CHANGE_ROLLBACK_EVIDENCE_MISSING:chg-phase3-001")


def test_emergency_change_without_retrospective_approval_blocks(manifest: dict) -> None:
    change = _control(manifest, "change_management_governance")["changes"][0]
    change["emergency_change"] = True
    change["retrospective_approval"] = "PENDING"

    _assert_blocked(manifest, "PR3_CHANGE_EMERGENCY_RETROSPECTIVE_APPROVAL_MISSING:chg-phase3-001")


def test_evidence_export_determinism(manifest: dict) -> None:
    result = _ready(manifest)

    first = export_phase3_evidence(result)
    second = export_phase3_evidence(result)

    assert first == second
    assert first["evidence_export_hash"].startswith("sha256:")


def test_evidence_export_excludes_sensitive_fields(manifest: dict) -> None:
    export = export_phase3_evidence(_ready(manifest))

    rendered = str(export)
    for forbidden in ("secret_value", "private_key", "raw_payload", "approval_contents", "password"):
        assert forbidden not in rendered


def test_evaluator_exception_returns_blocked(monkeypatch, manifest: dict) -> None:
    import governance.production_readiness_phase3 as phase3

    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(phase3, "_evaluate_control", explode)

    result = phase3.evaluate_phase3_readiness(manifest, commit_sha=COMMIT_SHA, branch=BRANCH, timestamp=TIMESTAMP)

    assert result.readiness_outcome == BLOCKED
    assert result.blockers == ("PR3_EVALUATOR_EXCEPTION",)


def test_ready_does_not_set_execution_flags(manifest: dict) -> None:
    result = _ready(manifest)

    assert result.readiness_outcome == READY
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.release_authorized is False


def test_execution_allowed_remains_false(manifest: dict) -> None:
    assert _ready(manifest).execution_allowed is False


def test_provider_execution_remains_false(manifest: dict) -> None:
    assert _ready(manifest).provider_execution is False


def test_production_activation_remains_false(manifest: dict) -> None:
    assert _ready(manifest).production_activation is False


def test_deployment_authorized_remains_false(manifest: dict) -> None:
    assert _ready(manifest).deployment_authorized is False


def test_release_authorized_remains_false(manifest: dict) -> None:
    assert _ready(manifest).release_authorized is False


def test_manifest_execution_flag_true_blocks(manifest: dict) -> None:
    manifest["execution_allowed"] = True

    _assert_blocked(manifest, "PR3_EXECUTION_FLAG_NOT_FALSE:execution_allowed")


def test_unknown_control_status_blocks(manifest: dict) -> None:
    _control(manifest, "backup_governance")["status"] = "UNKNOWN"

    _assert_blocked(manifest, "PR3_CONTROL_STATUS_INVALID:backup_governance")
