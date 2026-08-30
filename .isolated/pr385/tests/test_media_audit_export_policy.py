from __future__ import annotations

from tests.helpers.media_audit_export_policy import (
    load_media_audit_export_manifest,
    load_media_audit_export_policy,
    valid_audit_export_manifest,
    verify_media_audit_export_manifest,
)


def test_valid_audit_export_manifest_passes() -> None:
    evidence = verify_media_audit_export_manifest(valid_audit_export_manifest())

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_AUDIT_EXPORT_MANIFEST_VALID"
    assert evidence["export_contains_references_only"] is True
    assert evidence["production_export_signature"] is False


def test_export_without_scope_fails_closed() -> None:
    manifest = valid_audit_export_manifest()
    manifest["export_scope"] = ""

    evidence = verify_media_audit_export_manifest(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_AUDIT_EXPORT_SCOPE_MISSING"
    assert evidence["silent_pass"] is False


def test_export_with_scope_mismatch_fails_closed() -> None:
    manifest = valid_audit_export_manifest()
    manifest["export_scope"] = "public_release"

    evidence = verify_media_audit_export_manifest(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_AUDIT_EXPORT_SCOPE_UNAPPROVED"
    assert evidence["silent_pass"] is False


def test_export_without_provenance_chain_fails_closed() -> None:
    manifest = valid_audit_export_manifest()
    manifest["provenance_reference"] = ""

    evidence = verify_media_audit_export_manifest(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_AUDIT_EXPORT_LINEAGE_MISSING"
    assert evidence["silent_pass"] is False


def test_export_without_approval_chain_fails_closed() -> None:
    manifest = valid_audit_export_manifest()
    manifest["approval_chain_reference"] = ""

    evidence = verify_media_audit_export_manifest(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_AUDIT_EXPORT_LINEAGE_MISSING"
    assert evidence["silent_pass"] is False


def test_export_with_revoked_authority_fails_closed() -> None:
    manifest = valid_audit_export_manifest()
    manifest["revocation_reference"] = ""

    evidence = verify_media_audit_export_manifest(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_AUDIT_EXPORT_LINEAGE_MISSING"
    assert evidence["silent_pass"] is False


def test_sensitive_payload_markers_fail_closed() -> None:
    manifest = valid_audit_export_manifest()
    manifest["export_payload"] = "raw_audio=..."

    evidence = verify_media_audit_export_manifest(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_AUDIT_EXPORT_SENSITIVE_PAYLOAD_DETECTED"
    assert evidence["silent_pass"] is False


def test_unsigned_export_manifest_fails_closed() -> None:
    manifest = valid_audit_export_manifest()
    manifest["signature_placeholder"] = ""

    evidence = verify_media_audit_export_manifest(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_AUDIT_EXPORT_MANIFEST_UNSIGNED"
    assert evidence["silent_pass"] is False


def test_regulator_export_contains_references_only_not_payloads() -> None:
    manifest = load_media_audit_export_manifest()
    evidence = verify_media_audit_export_manifest(manifest)

    assert evidence["decision"] == "PASS"
    for forbidden_field in ("raw_media", "raw_audio", "raw_video", "contract", "oauth" + "_token", "personal_data"):
        assert forbidden_field not in manifest


def test_media_audit_export_policy_is_non_production_scaffolding() -> None:
    policy = load_media_audit_export_policy()

    assert policy["regulator_export_allowed"] is True
    assert policy["export_requires_approval_chain"] is True
    assert policy["export_requires_timestamp_chain"] is True
    assert policy["export_requires_provenance_chain"] is True
    assert policy["export_requires_distribution_lineage"] is True
    assert policy["export_requires_revocation_state"] is True
    assert policy["fail_closed_on_missing_audit_lineage"] is True
    assert policy["fail_closed_on_unsigned_export_manifest"] is True
    assert policy["fail_closed_on_sensitive_payload_detection"] is True
    assert policy["fail_closed_on_missing_export_scope"] is True
    assert policy["non_production_scaffolding"] is True
    assert set(policy["export_scopes"]) == {
        "regulator_review",
        "legal_dispute",
        "internal_audit",
        "platform_takedown_review",
        "rights_dispute_review",
    }
