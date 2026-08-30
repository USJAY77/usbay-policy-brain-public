from __future__ import annotations

from tests.helpers.media_release_token_policy import (
    load_media_release_token_policy,
    valid_release_token,
    verify_media_release_token,
)


MEDIA_ASSET_ID = "usbay-demo-media-asset-001"


def test_valid_release_token_passes() -> None:
    evidence = verify_media_release_token(valid_release_token(MEDIA_ASSET_ID), media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_RELEASE_TOKEN_VALID"
    assert evidence["production_release_token"] is False


def test_missing_release_token_fails_closed() -> None:
    evidence = verify_media_release_token(None, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RELEASE_TOKEN_MISSING"
    assert evidence["silent_pass"] is False


def test_expired_release_token_fails_closed() -> None:
    token = valid_release_token(MEDIA_ASSET_ID)
    token["expires_at"] = "2026-05-24T00:00:00Z"

    evidence = verify_media_release_token(token, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RELEASE_TOKEN_EXPIRED"
    assert evidence["silent_pass"] is False


def test_wrong_media_asset_id_fails_closed() -> None:
    token = valid_release_token("other-media-asset")

    evidence = verify_media_release_token(token, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RELEASE_TOKEN_SCOPE_INVALID"
    assert evidence["silent_pass"] is False


def test_token_without_rights_consent_evidence_fails_closed() -> None:
    token = valid_release_token(MEDIA_ASSET_ID)
    token["rights_consent_bound"] = False

    evidence = verify_media_release_token(token, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RELEASE_TOKEN_RIGHTS_CONSENT_MISSING"
    assert evidence["silent_pass"] is False


def test_token_without_timestamp_fails_closed() -> None:
    token = valid_release_token(MEDIA_ASSET_ID)
    token["timestamp_bound"] = False

    evidence = verify_media_release_token(token, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RELEASE_TOKEN_TIMESTAMP_MISSING"
    assert evidence["silent_pass"] is False


def test_token_without_approval_chain_fails_closed() -> None:
    token = valid_release_token(MEDIA_ASSET_ID)
    token["approval_chain_bound"] = False

    evidence = verify_media_release_token(token, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RELEASE_TOKEN_APPROVAL_CHAIN_MISSING"
    assert evidence["silent_pass"] is False


def test_release_token_policy_is_non_production_scaffolding() -> None:
    policy = load_media_release_token_policy()

    assert policy["release_token_required"] is True
    assert policy["release_token_scope"] == "media_asset_id"
    assert policy["approval_chain_required"] is True
    assert policy["timestamp_required"] is True
    assert policy["provenance_hash_required"] is True
    assert policy["rights_consent_required"] is True
    assert policy["non_production_scaffolding"] is True
