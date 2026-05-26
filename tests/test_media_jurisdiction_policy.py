from __future__ import annotations

from tests.helpers.media_jurisdiction_policy import (
    load_media_jurisdiction_export_manifest,
    load_media_jurisdiction_policy,
    valid_jurisdiction_evidence,
    verify_jurisdiction_export_manifest,
    verify_media_jurisdiction,
)


MEDIA_ASSET_ID = "usbay-demo-media-asset-001"


def test_valid_jurisdiction_evidence_passes() -> None:
    evidence = verify_media_jurisdiction(
        valid_jurisdiction_evidence(MEDIA_ASSET_ID),
        media_asset_id=MEDIA_ASSET_ID,
        platform="spotify",
    )

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_JURISDICTION_GOVERNANCE_VALID"


def test_unknown_jurisdiction_fails_closed() -> None:
    jurisdiction = valid_jurisdiction_evidence(MEDIA_ASSET_ID, jurisdiction="unknown_region")

    evidence = verify_media_jurisdiction(jurisdiction, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_JURISDICTION_UNKNOWN"
    assert evidence["silent_pass"] is False


def test_revoked_rights_in_one_region_block_distribution_in_that_region() -> None:
    jurisdiction = valid_jurisdiction_evidence(MEDIA_ASSET_ID, jurisdiction="us_media_rights")
    jurisdiction["regional_rights_active"] = False

    evidence = verify_media_jurisdiction(jurisdiction, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_REGIONAL_RIGHTS_REVOKED"
    assert evidence["silent_pass"] is False


def test_cross_region_policy_conflict_fails_closed() -> None:
    jurisdiction = valid_jurisdiction_evidence(MEDIA_ASSET_ID)
    jurisdiction["cross_jurisdiction_conflict"] = True

    evidence = verify_media_jurisdiction(jurisdiction, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_CROSS_JURISDICTION_CONFLICT"
    assert evidence["silent_pass"] is False


def test_restricted_platform_distribution_fails_closed() -> None:
    jurisdiction = valid_jurisdiction_evidence(MEDIA_ASSET_ID)
    jurisdiction["platform_restricted"] = True

    evidence = verify_media_jurisdiction(jurisdiction, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_RESTRICTED_PLATFORM_DISTRIBUTION"
    assert evidence["silent_pass"] is False


def test_expired_regional_rights_fail_closed() -> None:
    jurisdiction = valid_jurisdiction_evidence(MEDIA_ASSET_ID)
    jurisdiction["regional_rights_expires_at"] = "2026-05-25T00:00:00Z"

    evidence = verify_media_jurisdiction(jurisdiction, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_REGIONAL_RIGHTS_EXPIRED"
    assert evidence["silent_pass"] is False


def test_missing_regional_consent_fails_closed() -> None:
    jurisdiction = valid_jurisdiction_evidence(MEDIA_ASSET_ID)
    jurisdiction["regional_consent_active"] = False

    evidence = verify_media_jurisdiction(jurisdiction, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_REGIONAL_CONSENT_MISSING"
    assert evidence["silent_pass"] is False


def test_audit_export_without_jurisdiction_scope_fails_closed() -> None:
    manifest = load_media_jurisdiction_export_manifest()
    manifest["jurisdiction_scope"] = ""

    evidence = verify_jurisdiction_export_manifest(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_AUDIT_EXPORT_JURISDICTION_SCOPE_MISSING"
    assert evidence["silent_pass"] is False


def test_emergency_freeze_propagates_across_linked_jurisdictions() -> None:
    jurisdiction = valid_jurisdiction_evidence(MEDIA_ASSET_ID, jurisdiction="uk_broadcast_rules")
    jurisdiction["linked_emergency_freeze"] = True

    evidence = verify_media_jurisdiction(jurisdiction, media_asset_id=MEDIA_ASSET_ID, platform="spotify")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_JURISDICTION_EMERGENCY_FREEZE_PROPAGATED"
    assert evidence["silent_pass"] is False


def test_jurisdiction_export_manifest_contains_references_only() -> None:
    manifest = load_media_jurisdiction_export_manifest()
    evidence = verify_jurisdiction_export_manifest(manifest)

    assert evidence["decision"] == "PASS"
    assert evidence["export_contains_references_only"] is True
    for forbidden_field in ("raw_media", "legal_contract", "oauth" + "_token", "personal_data"):
        assert forbidden_field not in manifest


def test_media_jurisdiction_policy_is_non_production_scaffolding() -> None:
    policy = load_media_jurisdiction_policy()

    assert policy["jurisdiction_scope_required"] is True
    assert policy["fail_closed_on_unknown_jurisdiction"] is True
    assert policy["fail_closed_on_cross_jurisdiction_conflict"] is True
    assert policy["fail_closed_on_expired_regional_rights"] is True
    assert policy["fail_closed_on_missing_regional_consent"] is True
    assert policy["fail_closed_on_region_locked_distribution"] is True
    assert policy["fail_closed_on_restricted_platform_distribution"] is True
    assert policy["audit_export_requires_jurisdiction_scope"] is True
    assert policy["revocation_respected_across_regions"] is True
    assert policy["non_production_scaffolding"] is True
    assert set(policy["placeholder_jurisdictions"]) == {
        "eu_ai_act",
        "us_media_rights",
        "uk_broadcast_rules",
        "jp_media_distribution",
        "global_restricted",
    }
