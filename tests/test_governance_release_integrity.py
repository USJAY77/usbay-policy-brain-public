from __future__ import annotations

import json
from pathlib import Path

import pytest

from governance.release_integrity import (
    DEFAULT_BASELINE_TAG,
    GovernanceReleaseIntegrityError,
    build_release_integrity_manifest,
    release_integrity_hash,
    sign_release_integrity_manifest,
    validate_release_integrity_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


def _manifest() -> dict:
    return build_release_integrity_manifest(
        ROOT,
        release_id="test-governance-release",
        governance_baseline_tag=DEFAULT_BASELINE_TAG,
        generated_at="2026-05-12T00:00:00Z",
    )


def test_valid_governance_release_integrity_manifest_passes() -> None:
    manifest = _manifest()

    summary = validate_release_integrity_manifest(manifest, ROOT, expected_baseline_tag=DEFAULT_BASELINE_TAG)

    assert summary.valid is True
    assert summary.release_id == "test-governance-release"
    assert summary.release_hash == release_integrity_hash(manifest)


def test_release_tampering_fails_closed() -> None:
    manifest = _manifest()
    manifest["dependency_graph_hash"] = "0" * 64

    with pytest.raises(GovernanceReleaseIntegrityError) as exc:
        validate_release_integrity_manifest(manifest, ROOT, expected_baseline_tag=DEFAULT_BASELINE_TAG)

    assert "release_integrity_signature_invalid" in str(exc.value)
    assert "release_integrity_dependency_drift" in str(exc.value)


def test_tag_drift_fails_closed() -> None:
    manifest = _manifest()
    manifest["governance_baseline"]["tag_commit"] = "0" * 40
    manifest["release_signature"] = sign_release_integrity_manifest(manifest)

    with pytest.raises(GovernanceReleaseIntegrityError) as exc:
        validate_release_integrity_manifest(manifest, ROOT, expected_baseline_tag=DEFAULT_BASELINE_TAG)

    assert "release_integrity_tag_drift" in str(exc.value)


def test_baseline_mismatch_fails_closed() -> None:
    manifest = _manifest()

    with pytest.raises(GovernanceReleaseIntegrityError) as exc:
        validate_release_integrity_manifest(manifest, ROOT, expected_baseline_tag="different-baseline")

    assert "release_integrity_baseline_mismatch" in str(exc.value)


def test_rollback_corruption_fails_closed() -> None:
    previous = _manifest()
    current = build_release_integrity_manifest(
        ROOT,
        release_id="test-governance-release-2",
        governance_baseline_tag=DEFAULT_BASELINE_TAG,
        generated_at="2026-05-12T00:01:00Z",
        previous_manifest=previous,
    )
    current["audit_metadata"]["previous_release_hash"] = "f" * 64
    current["release_signature"] = sign_release_integrity_manifest(current)

    with pytest.raises(GovernanceReleaseIntegrityError) as exc:
        validate_release_integrity_manifest(current, ROOT, expected_baseline_tag=DEFAULT_BASELINE_TAG)

    assert "release_integrity_rollback_target_invalid" in str(exc.value)


def test_signed_rollback_target_passes_when_explicitly_allowed() -> None:
    previous = _manifest()
    current = build_release_integrity_manifest(
        ROOT,
        release_id="test-governance-release-2",
        governance_baseline_tag=DEFAULT_BASELINE_TAG,
        generated_at="2026-05-12T00:01:00Z",
        previous_manifest=previous,
    )
    previous_hash = release_integrity_hash(previous)

    summary = validate_release_integrity_manifest(
        current,
        ROOT,
        expected_baseline_tag=DEFAULT_BASELINE_TAG,
        rollback_targets=(previous_hash,),
    )

    assert summary.valid is True


def test_unsigned_release_metadata_fails_closed() -> None:
    manifest = _manifest()
    del manifest["release_signature"]

    with pytest.raises(GovernanceReleaseIntegrityError) as exc:
        validate_release_integrity_manifest(manifest, ROOT, expected_baseline_tag=DEFAULT_BASELINE_TAG)

    assert "release_integrity_field_missing:release_signature" in str(exc.value)
    assert "release_integrity_signature_invalid" in str(exc.value)


def test_release_integrity_manifest_is_deterministic_json_safe() -> None:
    manifest = _manifest()

    encoded = json.dumps(manifest, sort_keys=True)

    assert "PRIVATE KEY" not in encoded
    assert "raw_secret" not in encoded
