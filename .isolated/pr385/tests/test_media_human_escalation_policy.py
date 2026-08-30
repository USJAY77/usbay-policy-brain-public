from __future__ import annotations

from tests.helpers.media_human_escalation_policy import (
    load_media_human_escalation_manifest,
    load_media_human_escalation_policy,
    valid_human_escalation_evidence,
    verify_human_escalation,
    verify_human_escalation_manifest,
)


def test_valid_human_escalation_evidence_passes() -> None:
    evidence = verify_human_escalation(valid_human_escalation_evidence())

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_HUMAN_ESCALATION_VALID"
    assert evidence["human_escalation_audit_visible"] is True


def test_governance_critical_without_human_review_fails_closed() -> None:
    escalation = valid_human_escalation_evidence()
    escalation["governance_health_score"] = 40
    escalation["escalation_state"] = "ESCALATION_REVIEW_REQUIRED"

    evidence = verify_human_escalation(escalation)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_GOVERNANCE_CRITICAL_WITHOUT_REVIEW"
    assert evidence["silent_pass"] is False


def test_unresolved_crisis_state_blocks_verified_release() -> None:
    escalation = valid_human_escalation_evidence()
    escalation["escalation_state"] = "CRISIS_GOVERNANCE_ACTIVE"

    evidence = verify_human_escalation(escalation)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_UNRESOLVED_CRISIS_STATE"
    assert evidence["silent_pass"] is False


def test_repeated_revocation_crisis_escalates_governance_state() -> None:
    escalation = valid_human_escalation_evidence()
    escalation["mass_revocation_count"] = 3

    evidence = verify_human_escalation(escalation)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_MASS_REVOCATION_EVENT"
    assert evidence["silent_pass"] is False


def test_escalation_timeout_fails_closed() -> None:
    escalation = valid_human_escalation_evidence()
    escalation["escalation_response_time"] = 3601

    evidence = verify_human_escalation(escalation)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_ESCALATION_TIMEOUT"
    assert evidence["silent_pass"] is False


def test_unresolved_regulator_dispute_blocks_distribution() -> None:
    escalation = valid_human_escalation_evidence()
    escalation["regulator_dispute_count"] = 1

    evidence = verify_human_escalation(escalation)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_REGULATOR_DISPUTE_ESCALATION"
    assert evidence["silent_pass"] is False


def test_multi_region_crisis_conflict_fails_closed() -> None:
    escalation = valid_human_escalation_evidence()
    escalation["multi_region_conflict"] = True

    evidence = verify_human_escalation(escalation)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_MULTI_REGION_CRISIS_CONFLICT"
    assert evidence["silent_pass"] is False


def test_missing_escalation_chain_fails_closed() -> None:
    escalation = valid_human_escalation_evidence()
    escalation["escalation_chain_present"] = False

    evidence = verify_human_escalation(escalation)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_ESCALATION_CHAIN_MISSING"
    assert evidence["silent_pass"] is False


def test_human_escalation_manifest_passes() -> None:
    evidence = verify_human_escalation_manifest(load_media_human_escalation_manifest())

    assert evidence["decision"] == "PASS"
    assert evidence["human_escalation_audit_visible"] is True


def test_human_escalation_policy_is_non_production_scaffolding() -> None:
    policy = load_media_human_escalation_policy()

    assert policy["human_escalation_required"] is True
    assert policy["fail_closed_on_missing_human_review"] is True
    assert policy["fail_closed_on_unresolved_crisis_state"] is True
    assert policy["fail_closed_on_missing_escalation_chain"] is True
    assert policy["fail_closed_on_escalation_timeout"] is True
    assert policy["fail_closed_on_mass_revocation_event"] is True
    assert policy["fail_closed_on_regulator_dispute_escalation"] is True
    assert policy["fail_closed_on_multi_region_conflict"] is True
    assert policy["fail_closed_on_governance_critical_without_review"] is True
    assert policy["escalation_chain_required"] is True
    assert policy["non_production_scaffolding"] is True
    assert set(policy["escalation_states"]) == {
        "ESCALATION_PENDING",
        "ESCALATION_REVIEW_REQUIRED",
        "ESCALATION_IN_PROGRESS",
        "ESCALATION_APPROVED",
        "ESCALATION_REJECTED",
        "CRISIS_GOVERNANCE_ACTIVE",
        "GOVERNANCE_FAIL_CLOSED",
    }
