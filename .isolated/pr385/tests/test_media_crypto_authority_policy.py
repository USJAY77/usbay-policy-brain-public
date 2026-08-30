from __future__ import annotations

from tests.helpers.media_crypto_authority_policy import (
    load_media_crypto_authority_policy,
    valid_crypto_authority_manifest,
    verify_media_crypto_authority,
)


def test_valid_crypto_authority_manifest_passes() -> None:
    evidence = verify_media_crypto_authority(valid_crypto_authority_manifest())

    assert evidence["decision"] == "PASS"
    assert evidence["crypto_authority_reference_only"] is True


def test_missing_crypto_authority_manifest_fails_closed() -> None:
    evidence = verify_media_crypto_authority(None)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_CRYPTO_AUTHORITY_MANIFEST_MISSING"


def test_missing_signature_reference_fails_closed() -> None:
    manifest = valid_crypto_authority_manifest()
    manifest["approval_signature_reference"] = ""

    evidence = verify_media_crypto_authority(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_CRYPTO_SIGNATURE_REFERENCE_MISSING"


def test_unknown_signing_authority_fails_closed() -> None:
    manifest = valid_crypto_authority_manifest()
    manifest["signing_authority"] = "UNKNOWN_PLACEHOLDER_AUTHORITY"

    evidence = verify_media_crypto_authority(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_CRYPTO_SIGNING_AUTHORITY_UNKNOWN"


def test_stale_key_reference_fails_closed() -> None:
    manifest = valid_crypto_authority_manifest()
    manifest["key_reference_fresh"] = False

    evidence = verify_media_crypto_authority(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_CRYPTO_KEY_REFERENCE_STALE"


def test_unbound_signature_scope_fails_closed() -> None:
    manifest = valid_crypto_authority_manifest()
    manifest["signature_scope_bound"] = False

    evidence = verify_media_crypto_authority(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_CRYPTO_SIGNATURE_SCOPE_UNBOUND"


def test_crypto_authority_policy_is_non_production_scaffolding() -> None:
    policy = load_media_crypto_authority_policy()

    assert policy["signed_approval_reference_required"] is True
    assert policy["signed_recovery_reference_required"] is True
    assert policy["signed_escalation_reference_required"] is True
    assert policy["signed_manifest_reference_required"] is True
    assert policy["fail_closed_on_missing_signature_reference"] is True
    assert policy["fail_closed_on_unknown_signing_authority"] is True
    assert policy["fail_closed_on_stale_key_reference"] is True
    assert policy["fail_closed_on_unbound_signature_scope"] is True
    assert policy["non_production_scaffolding"] is True
