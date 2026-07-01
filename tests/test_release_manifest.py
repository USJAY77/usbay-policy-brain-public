from __future__ import annotations

import pytest

from governance.release_manifest import build_release_manifest, validate_release_manifest


pytestmark = pytest.mark.governance


def manifest(**overrides):
    payload = {
        "manifest_id": "manifest-1",
        "release_id": "rel-1",
        "policy_version": "policy-v1",
        "policy_hash": "p" * 64,
        "evidence_hash": "e" * 64,
        "audit_registry_hash": "a" * 64,
        "test_summary_hash": "t" * 64,
        "rollback_plan_hash": "r" * 64,
        "target_environment": "STAGING",
        "created_at": "2026-06-18T08:00:00Z",
        "created_by": "human-1",
        "lineage_hash": "l" * 64,
        "status": "BLOCKED",
        "reason_codes": [],
    }
    payload.update(overrides)
    return build_release_manifest(**payload)


def test_valid_manifest_is_ready():
    status, reasons = validate_release_manifest(manifest())

    assert status == "READY"
    assert reasons == ()


def test_missing_required_manifest_hash_blocks():
    status, reasons = validate_release_manifest(manifest(rollback_plan_hash=""))

    assert status == "BLOCKED"
    assert "RELEASE_MANIFEST_ROLLBACK_PLAN_HASH_MISSING" in reasons


def test_no_raw_secret_fields_in_manifest():
    status, reasons = validate_release_manifest(manifest(created_by="contains secret token"))

    assert status == "BLOCKED"
    assert "RELEASE_MANIFEST_SENSITIVE_PAYLOAD_BLOCKED" in reasons


def test_manifest_hash_mismatch_blocks():
    payload = manifest()
    payload["policy_hash"] = "changed"

    status, reasons = validate_release_manifest(payload)

    assert status == "BLOCKED"
    assert "RELEASE_MANIFEST_HASH_MISMATCH" in reasons
