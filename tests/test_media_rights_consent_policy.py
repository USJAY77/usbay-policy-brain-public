from __future__ import annotations

from tests.helpers.media_rights_consent_policy import (
    load_media_rights_policy,
    valid_rights_consent_evidence,
    verify_media_rights_consent,
)


def test_valid_rights_and_consent_evidence_passes() -> None:
    evidence = verify_media_rights_consent(valid_rights_consent_evidence())

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_RIGHTS_CONSENT_VALID"
    assert evidence["non_production_scaffolding"] is True


def test_missing_actor_consent_fails_closed() -> None:
    rights = valid_rights_consent_evidence()
    rights["actor_consent"]["approved"] = False

    evidence = verify_media_rights_consent(rights)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_ACTOR_CONSENT_MISSING"
    assert evidence["silent_pass"] is False


def test_missing_voice_consent_fails_closed() -> None:
    rights = valid_rights_consent_evidence()
    rights["voice_consent"]["approved"] = False

    evidence = verify_media_rights_consent(rights)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_VOICE_CONSENT_MISSING"
    assert evidence["silent_pass"] is False


def test_missing_sample_clearance_fails_closed() -> None:
    rights = valid_rights_consent_evidence()
    rights["music_sample_clearance"]["approved"] = False

    evidence = verify_media_rights_consent(rights)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_SAMPLE_CLEARANCE_MISSING"
    assert evidence["silent_pass"] is False


def test_expired_consent_fails_closed() -> None:
    rights = valid_rights_consent_evidence()
    rights["actor_consent"]["expires_at"] = "2026-05-24T00:00:00Z"

    evidence = verify_media_rights_consent(rights)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_CONSENT_EXPIRED"
    assert evidence["silent_pass"] is False


def test_missing_legal_review_fails_closed() -> None:
    rights = valid_rights_consent_evidence()
    rights["legal_reviewer_approval"]["approved"] = False

    evidence = verify_media_rights_consent(rights)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_LEGAL_REVIEW_MISSING"
    assert evidence["silent_pass"] is False


def test_missing_dataset_source_authorization_fails_closed() -> None:
    rights = valid_rights_consent_evidence()
    rights["dataset_source_authorization"]["approved"] = False

    evidence = verify_media_rights_consent(rights)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DATASET_SOURCE_AUTHORIZATION_MISSING"
    assert evidence["silent_pass"] is False


def test_media_rights_policy_is_explicit_non_production_scaffolding() -> None:
    policy = load_media_rights_policy()

    assert policy["fail_closed_on_missing_consent"] is True
    assert policy["fail_closed_on_expired_consent"] is True
    assert policy["non_production_scaffolding"] is True
    assert policy["legal_reviewer_approval_required"] is True
    assert policy["royalty_review_required"] is True
