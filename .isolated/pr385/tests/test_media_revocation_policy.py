from __future__ import annotations

from tests.helpers.media_revocation_policy import (
    load_media_revocation_policy,
    valid_revocation_state,
    verify_media_revocation_state,
)


MEDIA_ASSET_ID = "usbay-demo-media-asset-001"


def test_valid_distribution_authorized_state_passes() -> None:
    evidence = verify_media_revocation_state(valid_revocation_state(MEDIA_ASSET_ID), media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_REVOCATION_STATE_DISTRIBUTABLE"
    assert evidence["revocation_override_active"] is False


def test_revoked_release_token_blocks_distribution() -> None:
    state = valid_revocation_state(MEDIA_ASSET_ID)
    state["release_token_revoked"] = True

    evidence = verify_media_revocation_state(state, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RELEASE_TOKEN_REVOKED"
    assert evidence["silent_pass"] is False


def test_frozen_media_asset_fails_closed() -> None:
    state = valid_revocation_state(MEDIA_ASSET_ID)
    state["release_state"] = "EMERGENCY_FROZEN"

    evidence = verify_media_revocation_state(state, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_EMERGENCY_FROZEN"
    assert evidence["silent_pass"] is False


def test_revoked_rights_consent_fails_closed_after_release() -> None:
    state = valid_revocation_state(MEDIA_ASSET_ID)
    state["rights_consent_revoked"] = True

    evidence = verify_media_revocation_state(state, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RIGHTS_CONSENT_REVOKED"
    assert evidence["silent_pass"] is False


def test_platform_takedown_state_blocks_publication() -> None:
    state = valid_revocation_state(MEDIA_ASSET_ID)
    state["release_state"] = "PLATFORM_TAKEDOWN_REQUIRED"

    evidence = verify_media_revocation_state(state, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_PLATFORM_TAKEDOWN_REQUIRED"
    assert evidence["silent_pass"] is False


def test_dispute_hold_blocks_distribution() -> None:
    state = valid_revocation_state(MEDIA_ASSET_ID)
    state["release_state"] = "LEGAL_DISPUTE_HOLD"

    evidence = verify_media_revocation_state(state, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_LEGAL_DISPUTE_HOLD"
    assert evidence["silent_pass"] is False


def test_revoked_distribution_authority_fails_closed() -> None:
    state = valid_revocation_state(MEDIA_ASSET_ID)
    state["distribution_authority_active"] = False

    evidence = verify_media_revocation_state(state, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_AUTHORITY_REVOKED"
    assert evidence["silent_pass"] is False


def test_expired_distribution_authority_fails_closed() -> None:
    state = valid_revocation_state(MEDIA_ASSET_ID)
    state["distribution_authority_expires_at"] = "2026-05-25T00:00:00Z"

    evidence = verify_media_revocation_state(state, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_AUTHORITY_EXPIRED"
    assert evidence["silent_pass"] is False


def test_revocation_policy_is_non_production_scaffolding() -> None:
    policy = load_media_revocation_policy()

    assert policy["emergency_freeze_enabled"] is True
    assert policy["release_revocation_supported"] is True
    assert policy["takedown_review_required"] is True
    assert policy["fail_closed_on_revoked_release"] is True
    assert policy["fail_closed_on_frozen_asset"] is True
    assert policy["fail_closed_on_expired_distribution_authority"] is True
    assert policy["fail_closed_on_revoked_rights_consent"] is True
    assert policy["fail_closed_on_post_release_dispute"] is True
    assert policy["non_production_scaffolding"] is True
    assert set(policy["revocation_states"]) == {
        "VERIFIED_RELEASE",
        "DISTRIBUTION_AUTHORIZED",
        "RELEASE_REVOKED",
        "EMERGENCY_FROZEN",
        "LEGAL_DISPUTE_HOLD",
        "PLATFORM_TAKEDOWN_REQUIRED",
    }
