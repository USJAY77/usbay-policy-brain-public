from __future__ import annotations

from tests.helpers.media_redteam_policy import (
    load_media_redteam_manifest,
    load_media_redteam_policy,
    valid_redteam_evidence,
    verify_media_redteam,
    verify_media_redteam_manifest,
)


def test_valid_redteam_evidence_passes() -> None:
    evidence = verify_media_redteam(valid_redteam_evidence())

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_REDTEAM_GOVERNANCE_CLEAR"
    assert evidence["adversarial_governance_audit_visible"] is True


def test_forged_approval_chain_fails_closed() -> None:
    redteam = valid_redteam_evidence()
    redteam["forged_approval_attempts"] = 1

    evidence = verify_media_redteam(redteam)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_FORGED_APPROVAL_CHAIN_DETECTED"
    assert evidence["silent_pass"] is False


def test_lineage_corruption_fails_closed() -> None:
    redteam = valid_redteam_evidence()
    redteam["lineage_corruption_events"] = 1

    evidence = verify_media_redteam(redteam)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_LINEAGE_CORRUPTION_DETECTED"
    assert evidence["silent_pass"] is False


def test_timestamp_replay_attack_fails_closed() -> None:
    redteam = valid_redteam_evidence()
    redteam["replay_attack_attempts"] = 1

    evidence = verify_media_redteam(redteam)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_TIMESTAMP_REPLAY_ATTACK_DETECTED"
    assert evidence["silent_pass"] is False


def test_distribution_scope_spoofing_fails_closed() -> None:
    redteam = valid_redteam_evidence()
    redteam["spoofed_distribution_events"] = 1

    evidence = verify_media_redteam(redteam)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_SCOPE_SPOOFING_DETECTED"
    assert evidence["silent_pass"] is False


def test_fake_human_escalation_fails_closed() -> None:
    redteam = valid_redteam_evidence()
    redteam["fake_escalation_attempts"] = 1

    evidence = verify_media_redteam(redteam)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_FAKE_HUMAN_ESCALATION_DETECTED"
    assert evidence["silent_pass"] is False


def test_governance_bypass_attempt_fails_closed() -> None:
    redteam = valid_redteam_evidence()
    redteam["governance_bypass_attempts"] = 1

    evidence = verify_media_redteam(redteam)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_GOVERNANCE_BYPASS_ATTEMPT"
    assert evidence["silent_pass"] is False


def test_export_tampering_is_audit_visible() -> None:
    redteam = valid_redteam_evidence()
    redteam["export_tamper_events"] = 1

    evidence = verify_media_redteam(redteam)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_EXPORT_MANIFEST_TAMPERING_DETECTED"
    assert evidence["adversarial_governance_audit_visible"] is True
    assert evidence["silent_pass"] is False


def test_adversarial_governance_state_overrides_prior_pass_states() -> None:
    redteam = valid_redteam_evidence()
    redteam["governance_attack_state"] = "ADVERSARIAL_GOVERNANCE_DETECTED"

    evidence = verify_media_redteam(redteam)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_ADVERSARIAL_GOVERNANCE_DETECTED"
    assert evidence["silent_pass"] is False


def test_recovery_bypass_and_watchtower_suppression_fail_closed() -> None:
    recovery_bypass = valid_redteam_evidence()
    recovery_bypass["recovery_bypass_attempt"] = True
    watchtower_suppression = valid_redteam_evidence()
    watchtower_suppression["watchtower_suppression_attempt"] = True

    recovery_evidence = verify_media_redteam(recovery_bypass)
    watchtower_evidence = verify_media_redteam(watchtower_suppression)

    assert recovery_evidence["decision"] == "FAIL_CLOSED"
    assert recovery_evidence["reason"] == "MEDIA_RECOVERY_BYPASS_ATTEMPT"
    assert watchtower_evidence["decision"] == "FAIL_CLOSED"
    assert watchtower_evidence["reason"] == "MEDIA_WATCHTOWER_SUPPRESSION_ATTEMPT"


def test_cross_region_and_mass_drift_attacks_fail_closed() -> None:
    cross_region = valid_redteam_evidence()
    cross_region["cross_region_policy_conflict_attack"] = True
    mass_drift = valid_redteam_evidence()
    mass_drift["mass_governance_drift_event"] = True

    cross_region_evidence = verify_media_redteam(cross_region)
    mass_drift_evidence = verify_media_redteam(mass_drift)

    assert cross_region_evidence["decision"] == "FAIL_CLOSED"
    assert cross_region_evidence["reason"] == "MEDIA_CROSS_REGION_POLICY_CONFLICT_ATTACK"
    assert mass_drift_evidence["decision"] == "FAIL_CLOSED"
    assert mass_drift_evidence["reason"] == "MEDIA_MASS_GOVERNANCE_DRIFT_EVENT"


def test_redteam_manifest_passes() -> None:
    evidence = verify_media_redteam_manifest(load_media_redteam_manifest())

    assert evidence["decision"] == "PASS"
    assert evidence["adversarial_governance_audit_visible"] is True


def test_redteam_manifest_tampering_fails_closed() -> None:
    manifest = load_media_redteam_manifest()
    manifest["export_tamper_events"] = 1

    evidence = verify_media_redteam_manifest(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_EXPORT_MANIFEST_TAMPERING_DETECTED"
    assert evidence["silent_pass"] is False


def test_media_redteam_policy_is_non_production_scaffolding() -> None:
    policy = load_media_redteam_policy()

    assert policy["fail_closed_on_forged_approval_chain"] is True
    assert policy["fail_closed_on_lineage_corruption"] is True
    assert policy["fail_closed_on_timestamp_replay_attack"] is True
    assert policy["fail_closed_on_distribution_scope_spoofing"] is True
    assert policy["fail_closed_on_recovery_bypass_attempt"] is True
    assert policy["fail_closed_on_watchtower_suppression_attempt"] is True
    assert policy["fail_closed_on_fake_human_escalation"] is True
    assert policy["fail_closed_on_cross_region_policy_conflict_attack"] is True
    assert policy["fail_closed_on_mass_governance_drift_event"] is True
    assert policy["fail_closed_on_export_manifest_tampering"] is True
    assert policy["adversarial_governance_testing_enabled"] is True
    assert policy["non_production_scaffolding"] is True
    assert set(policy["adversarial_governance_states"]) == {
        "ADVERSARIAL_GOVERNANCE_DETECTED",
        "LINEAGE_COMPROMISE_DETECTED",
        "APPROVAL_FORGERY_DETECTED",
        "DISTRIBUTION_SPOOF_DETECTED",
        "GOVERNANCE_BYPASS_ATTEMPT",
        "GOVERNANCE_ATTACK_SIMULATION",
        "GOVERNANCE_FAIL_CLOSED",
    }
