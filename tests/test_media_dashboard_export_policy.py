from __future__ import annotations

from tests.helpers.media_dashboard_export_policy import (
    load_media_dashboard_export_policy,
    valid_dashboard_export_manifest,
    verify_media_dashboard_export,
)


def test_valid_dashboard_export_manifest_passes() -> None:
    evidence = verify_media_dashboard_export(valid_dashboard_export_manifest())

    assert evidence["decision"] == "PASS"
    assert evidence["dashboard_export_reference_only"] is True


def test_missing_dashboard_export_manifest_fails_closed() -> None:
    evidence = verify_media_dashboard_export(None)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DASHBOARD_EXPORT_MANIFEST_MISSING"


def test_unscoped_export_fails_closed() -> None:
    manifest = valid_dashboard_export_manifest()
    manifest["export_scope"] = ""

    evidence = verify_media_dashboard_export(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DASHBOARD_EXPORT_UNSCOPED"


def test_sensitive_payload_export_fails_closed() -> None:
    manifest = valid_dashboard_export_manifest()
    manifest["export_contains_sensitive_payload"] = True

    evidence = verify_media_dashboard_export(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DASHBOARD_EXPORT_SENSITIVE_PAYLOAD"


def test_missing_export_purpose_fails_closed() -> None:
    manifest = valid_dashboard_export_manifest()
    manifest["export_purpose"] = ""

    evidence = verify_media_dashboard_export(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DASHBOARD_EXPORT_PURPOSE_MISSING"


def test_missing_dashboard_references_fail_closed() -> None:
    manifest = valid_dashboard_export_manifest()
    manifest["lifecycle_graph_reference"] = ""

    evidence = verify_media_dashboard_export(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DASHBOARD_LIFECYCLE_GRAPH_REFERENCE_MISSING"


def test_dashboard_export_policy_is_non_production_scaffolding() -> None:
    policy = load_media_dashboard_export_policy()

    assert policy["lifecycle_graph_reference_required"] is True
    assert policy["audit_export_reference_required"] is True
    assert policy["regulator_export_reference_required"] is True
    assert policy["escalation_dashboard_reference_required"] is True
    assert policy["fail_closed_on_unscoped_export"] is True
    assert policy["fail_closed_on_sensitive_payload_export"] is True
    assert policy["fail_closed_on_missing_export_purpose"] is True
    assert policy["non_production_scaffolding"] is True
