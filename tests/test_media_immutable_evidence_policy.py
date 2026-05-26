from __future__ import annotations

from tests.helpers.media_immutable_evidence_policy import (
    load_media_immutable_evidence_policy,
    valid_immutable_evidence_manifest,
    verify_media_immutable_evidence,
)


def test_valid_immutable_evidence_manifest_passes() -> None:
    evidence = verify_media_immutable_evidence(valid_immutable_evidence_manifest())

    assert evidence["decision"] == "PASS"
    assert evidence["immutable_evidence_reference_only"] is True


def test_unsigned_evidence_bundle_fails_closed() -> None:
    manifest = valid_immutable_evidence_manifest()
    manifest["signature_reference"] = ""

    evidence = verify_media_immutable_evidence(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_EVIDENCE_BUNDLE_UNSIGNED"
    assert evidence["silent_pass"] is False


def test_missing_chain_hash_fails_closed() -> None:
    manifest = valid_immutable_evidence_manifest()
    manifest["chain_hash_reference"] = ""

    evidence = verify_media_immutable_evidence(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_EVIDENCE_CHAIN_HASH_MISSING"


def test_mutable_storage_marker_fails_closed() -> None:
    manifest = valid_immutable_evidence_manifest()
    manifest["mutable_storage_marker"] = True

    evidence = verify_media_immutable_evidence(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_EVIDENCE_MUTABLE_STORAGE_MARKER"


def test_missing_timestamp_reference_fails_closed() -> None:
    manifest = valid_immutable_evidence_manifest()
    manifest["timestamp_reference"] = ""

    evidence = verify_media_immutable_evidence(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_EVIDENCE_TIMESTAMP_REFERENCE_MISSING"


def test_lineage_gap_fails_closed() -> None:
    manifest = valid_immutable_evidence_manifest()
    manifest["lineage_gap_detected"] = True

    evidence = verify_media_immutable_evidence(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_EVIDENCE_LINEAGE_GAP"


def test_replay_without_evidence_anchor_fails_closed() -> None:
    manifest = valid_immutable_evidence_manifest()
    manifest["replay_anchor_present"] = False

    evidence = verify_media_immutable_evidence(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_REPLAY_WITHOUT_EVIDENCE_ANCHOR"


def test_immutable_policy_is_non_production_scaffolding() -> None:
    policy = load_media_immutable_evidence_policy()

    assert policy["fail_closed_on_unsigned_evidence_bundle"] is True
    assert policy["fail_closed_on_missing_chain_hash"] is True
    assert policy["fail_closed_on_mutable_storage_marker"] is True
    assert policy["fail_closed_on_missing_timestamp_reference"] is True
    assert policy["fail_closed_on_lineage_gap"] is True
    assert policy["fail_closed_on_replay_without_evidence_anchor"] is True
    assert policy["non_production_scaffolding"] is True
