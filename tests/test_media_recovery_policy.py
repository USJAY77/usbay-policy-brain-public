from __future__ import annotations

from tests.helpers.media_recovery_policy import (
    load_media_recovery_manifest,
    load_media_recovery_policy,
    valid_recovery_evidence,
    verify_media_recovery,
    verify_media_recovery_manifest,
)


def test_valid_recovery_evidence_passes() -> None:
    evidence = verify_media_recovery(valid_recovery_evidence())

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_RECOVERY_REAUTHORIZATION_VALID"
    assert evidence["reauthorization_audit_visible"] is True


def test_revoked_asset_cannot_reauthorize_without_recovery_review() -> None:
    recovery = valid_recovery_evidence()
    recovery["post_incident_review_completed"] = False

    evidence = verify_media_recovery(recovery)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RECOVERY_REVIEW_MISSING"
    assert evidence["silent_pass"] is False


def test_unresolved_incident_lineage_fails_closed() -> None:
    recovery = valid_recovery_evidence()
    recovery["incident_lineage_resolved"] = False

    evidence = verify_media_recovery(recovery)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RECOVERY_INCIDENT_LINEAGE_UNRESOLVED"
    assert evidence["silent_pass"] is False


def test_stale_recovery_evidence_fails_closed() -> None:
    recovery = valid_recovery_evidence()
    recovery["recovery_evidence_fresh"] = False

    evidence = verify_media_recovery(recovery)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RECOVERY_EVIDENCE_STALE"
    assert evidence["silent_pass"] is False


def test_repeat_incident_pattern_blocks_reauthorization() -> None:
    recovery = valid_recovery_evidence()
    recovery["repeat_incident_frequency"] = 2

    evidence = verify_media_recovery(recovery)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RECOVERY_REPEAT_INCIDENT_PATTERN"
    assert evidence["silent_pass"] is False


def test_watchtower_critical_state_blocks_recovery() -> None:
    recovery = valid_recovery_evidence()
    recovery["watchtower_clearance"] = False

    evidence = verify_media_recovery(recovery)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RECOVERY_WATCHTOWER_CLEARANCE_MISSING"
    assert evidence["silent_pass"] is False


def test_human_escalation_approval_required_before_recovery() -> None:
    recovery = valid_recovery_evidence()
    recovery["human_signoff"] = False

    evidence = verify_media_recovery(recovery)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RECOVERY_HUMAN_SIGNOFF_MISSING"
    assert evidence["silent_pass"] is False


def test_recovery_after_revocation_fails_closed_without_resolution() -> None:
    recovery = valid_recovery_evidence()
    recovery["revocation_resolved"] = False

    evidence = verify_media_recovery(recovery)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RECOVERY_AFTER_REVOCATION_BLOCKED"
    assert evidence["silent_pass"] is False


def test_recovery_after_jurisdiction_conflict_fails_closed_without_resolution() -> None:
    recovery = valid_recovery_evidence()
    recovery["jurisdiction_conflict_resolved"] = False

    evidence = verify_media_recovery(recovery)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RECOVERY_AFTER_JURISDICTION_CONFLICT_BLOCKED"
    assert evidence["silent_pass"] is False


def test_recovery_after_drift_without_reset_fails_closed() -> None:
    recovery = valid_recovery_evidence()
    recovery["drift_reset_completed"] = False

    evidence = verify_media_recovery(recovery)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RECOVERY_AFTER_DRIFT_WITHOUT_RESET"
    assert evidence["silent_pass"] is False


def test_recovery_manifest_passes() -> None:
    evidence = verify_media_recovery_manifest(load_media_recovery_manifest())

    assert evidence["decision"] == "PASS"
    assert evidence["reauthorization_audit_visible"] is True


def test_media_recovery_policy_is_non_production_scaffolding() -> None:
    policy = load_media_recovery_policy()

    assert policy["controlled_reauthorization_required"] is True
    assert policy["fail_closed_on_missing_recovery_review"] is True
    assert policy["fail_closed_on_unresolved_incident_lineage"] is True
    assert policy["fail_closed_on_stale_recovery_evidence"] is True
    assert policy["fail_closed_on_repeat_incident_pattern"] is True
    assert policy["fail_closed_on_recovery_without_human_signoff"] is True
    assert policy["fail_closed_on_recovery_without_watchtower_clearance"] is True
    assert policy["fail_closed_on_recovery_after_revocation"] is True
    assert policy["fail_closed_on_recovery_after_jurisdiction_conflict"] is True
    assert policy["fail_closed_on_recovery_after_drift_without_reset"] is True
    assert policy["post_incident_review_required"] is True
    assert policy["non_production_scaffolding"] is True
    assert set(policy["recovery_states"]) == {
        "RECOVERY_PENDING",
        "RECOVERY_REVIEW_REQUIRED",
        "RECOVERY_UNDER_INVESTIGATION",
        "RECOVERY_APPROVED",
        "RECOVERY_REJECTED",
        "REAUTHORIZATION_ALLOWED",
        "REAUTHORIZATION_BLOCKED",
        "GOVERNANCE_FAIL_CLOSED",
    }
