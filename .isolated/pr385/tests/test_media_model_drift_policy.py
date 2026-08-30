from __future__ import annotations

from tests.helpers.media_model_drift_policy import (
    load_media_drift_manifest,
    load_media_model_drift_policy,
    valid_drift_evidence,
    verify_media_drift_manifest,
    verify_media_model_drift,
)


MEDIA_ASSET_ID = "usbay-demo-media-asset-001"


def test_valid_model_drift_evidence_passes() -> None:
    evidence = verify_media_model_drift(valid_drift_evidence(MEDIA_ASSET_ID), media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_MODEL_DRIFT_GOVERNANCE_VALID"


def test_model_identity_mismatch_fails_closed() -> None:
    drift = valid_drift_evidence(MEDIA_ASSET_ID)
    drift["model_identifier"] = "other-model"

    evidence = verify_media_model_drift(drift, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_MODEL_IDENTITY_MISMATCH"
    assert evidence["silent_pass"] is False


def test_model_version_mismatch_fails_closed() -> None:
    drift = valid_drift_evidence(MEDIA_ASSET_ID)
    drift["model_version"] = "media-demo-model-v2"

    evidence = verify_media_model_drift(drift, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_MODEL_VERSION_DRIFT"
    assert evidence["silent_pass"] is False


def test_provenance_continuity_gap_fails_closed() -> None:
    drift = valid_drift_evidence(MEDIA_ASSET_ID)
    drift["provenance_continuity"] = False

    evidence = verify_media_model_drift(drift, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_PROVENANCE_CHAIN_GAP"
    assert evidence["silent_pass"] is False


def test_approval_chain_regression_fails_closed() -> None:
    drift = valid_drift_evidence(MEDIA_ASSET_ID)
    drift["approval_chain_regression"] = True

    evidence = verify_media_model_drift(drift, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_APPROVAL_CHAIN_REGRESSION"
    assert evidence["silent_pass"] is False


def test_export_schema_drift_fails_closed() -> None:
    drift = valid_drift_evidence(MEDIA_ASSET_ID)
    drift["export_schema_drift"] = True

    evidence = verify_media_model_drift(drift, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_EXPORT_SCHEMA_DRIFT"
    assert evidence["silent_pass"] is False


def test_jurisdiction_drift_fails_closed() -> None:
    drift = valid_drift_evidence(MEDIA_ASSET_ID)
    drift["jurisdiction_policy_drift"] = True

    evidence = verify_media_model_drift(drift, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_JURISDICTION_POLICY_DRIFT"
    assert evidence["silent_pass"] is False


def test_revocation_override_loss_fails_closed() -> None:
    drift = valid_drift_evidence(MEDIA_ASSET_ID)
    drift["revocation_override_present"] = False

    evidence = verify_media_model_drift(drift, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_REVOCATION_OVERRIDE_LOST"
    assert evidence["silent_pass"] is False


def test_stale_policy_lineage_fails_closed() -> None:
    drift = valid_drift_evidence(MEDIA_ASSET_ID)
    drift["policy_lineage_valid"] = False

    evidence = verify_media_model_drift(drift, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_POLICY_LINEAGE_BROKEN"
    assert evidence["silent_pass"] is False


def test_timestamp_chain_gap_fails_closed() -> None:
    drift = valid_drift_evidence(MEDIA_ASSET_ID)
    drift["timestamp_chain_continuity"] = False

    evidence = verify_media_model_drift(drift, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_TIMESTAMP_CHAIN_GAP"
    assert evidence["silent_pass"] is False


def test_distribution_scope_regression_fails_closed() -> None:
    drift = valid_drift_evidence(MEDIA_ASSET_ID)
    drift["distribution_scope_regression"] = True

    evidence = verify_media_model_drift(drift, media_asset_id=MEDIA_ASSET_ID)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_DISTRIBUTION_SCOPE_REGRESSION"
    assert evidence["silent_pass"] is False


def test_drift_manifest_with_drift_finding_fails_closed() -> None:
    manifest = load_media_drift_manifest()
    manifest["drift_findings"] = ["EXPORT_SCHEMA_DRIFT"]

    evidence = verify_media_drift_manifest(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_EXPORT_SCHEMA_DRIFT"
    assert evidence["silent_pass"] is False


def test_valid_drift_manifest_passes() -> None:
    evidence = verify_media_drift_manifest(load_media_drift_manifest())

    assert evidence["decision"] == "PASS"
    assert evidence["reason"] == "MEDIA_DRIFT_MANIFEST_VALID"


def test_model_drift_policy_is_non_production_scaffolding() -> None:
    policy = load_media_model_drift_policy()

    assert policy["fail_closed_on_model_identity_mismatch"] is True
    assert policy["fail_closed_on_model_version_drift"] is True
    assert policy["fail_closed_on_provenance_gap"] is True
    assert policy["fail_closed_on_policy_lineage_break"] is True
    assert policy["fail_closed_on_timestamp_chain_gap"] is True
    assert policy["fail_closed_on_jurisdiction_policy_drift"] is True
    assert policy["fail_closed_on_approval_chain_regression"] is True
    assert policy["fail_closed_on_export_schema_drift"] is True
    assert policy["fail_closed_on_distribution_scope_regression"] is True
    assert policy["fail_closed_on_revocation_override_loss"] is True
    assert policy["drift_review_required"] is True
    assert policy["non_production_scaffolding"] is True
    assert set(policy["drift_states"]) == {
        "MODEL_VERSION_DRIFT",
        "POLICY_LINEAGE_BROKEN",
        "PROVENANCE_CHAIN_GAP",
        "APPROVAL_REGRESSION",
        "JURISDICTION_POLICY_CONFLICT",
        "EXPORT_SCHEMA_DRIFT",
        "DISTRIBUTION_SCOPE_DRIFT",
        "REVOCATION_OVERRIDE_LOST",
    }
