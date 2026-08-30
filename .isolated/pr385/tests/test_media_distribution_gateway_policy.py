from __future__ import annotations

from tests.helpers.media_distribution_gateway_policy import (
    load_media_distribution_policy,
    valid_distribution_authorization,
    verify_distribution_authorization,
)


MEDIA_ASSET_ID = "usbay-demo-media-asset-001"


def test_valid_distribution_authorization_passes() -> None:
    evidence = verify_distribution_authorization(
        valid_distribution_authorization(MEDIA_ASSET_ID, "spotify"),
        media_asset_id=MEDIA_ASSET_ID,
        platform="spotify",
    )

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_AUTHORIZATION_VALID"
    assert evidence["production_distribution_authority"] is False


def test_unknown_platform_fails_closed() -> None:
    evidence = verify_distribution_authorization(
        valid_distribution_authorization(MEDIA_ASSET_ID, "unapproved_platform"),
        media_asset_id=MEDIA_ASSET_ID,
        platform="unapproved_platform",
    )

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_PLATFORM_UNKNOWN"
    assert evidence["silent_pass"] is False


def test_missing_distribution_authority_fails_closed() -> None:
    evidence = verify_distribution_authorization(None, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_AUTHORITY_MISSING"
    assert evidence["silent_pass"] is False


def test_wrong_platform_scope_fails_closed() -> None:
    authorization = valid_distribution_authorization(MEDIA_ASSET_ID, "spotify")
    authorization["platform_scope"] = "youtube"

    evidence = verify_distribution_authorization(authorization, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_PLATFORM_SCOPE_MISMATCH"
    assert evidence["silent_pass"] is False


def test_missing_rights_consent_fails_closed() -> None:
    authorization = valid_distribution_authorization(MEDIA_ASSET_ID, "spotify")
    authorization["rights_consent_bound"] = False

    evidence = verify_distribution_authorization(authorization, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_RIGHTS_CONSENT_MISSING"
    assert evidence["silent_pass"] is False


def test_unsigned_distribution_request_fails_closed() -> None:
    authorization = valid_distribution_authorization(MEDIA_ASSET_ID, "spotify")
    authorization["request_signature_state"] = "UNSIGNED"

    evidence = verify_distribution_authorization(authorization, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_REQUEST_UNSIGNED"
    assert evidence["silent_pass"] is False


def test_release_token_without_platform_authorization_fails_closed() -> None:
    authorization = valid_distribution_authorization(MEDIA_ASSET_ID, "spotify")
    authorization["release_token_bound"] = False

    evidence = verify_distribution_authorization(authorization, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_RELEASE_TOKEN_MISSING"
    assert evidence["silent_pass"] is False


def test_distribution_policy_is_non_production_scaffolding() -> None:
    policy = load_media_distribution_policy()

    assert policy["distributor_authorization_required"] is True
    assert policy["platform_scope_required"] is True
    assert policy["release_token_required"] is True
    assert policy["approval_chain_required"] is True
    assert policy["timestamp_required"] is True
    assert policy["provenance_required"] is True
    assert policy["rights_consent_required"] is True
    assert policy["non_production_scaffolding"] is True
    assert set(policy["supported_placeholder_platforms"]) == {
        "spotify",
        "youtube",
        "netflix",
        "broadcaster_internal",
        "studio_archive",
    }
