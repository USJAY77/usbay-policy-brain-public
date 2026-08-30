from __future__ import annotations

import pytest

from governance.evidence_contracts import (
    EVIDENCE_ARTIFACT_SCHEMA,
    EVIDENCE_MANIFEST_SCHEMA,
    EVIDENCE_POLICY_VERSION,
    validate_artifact_record,
    validate_evidence_manifest,
)


pytestmark = pytest.mark.governance


def artifact(**overrides):
    payload = {
        "schema": EVIDENCE_ARTIFACT_SCHEMA,
        "artifact_id": "artifact-1",
        "artifact_path": "governance/evidence/example.json",
        "artifact_schema": "usbay.example.v1",
        "artifact_hash": "a" * 64,
        "created_at": "2026-06-17T05:00:00Z",
        "source_pb": "PB-EVIDENCE",
        "policy_version": EVIDENCE_POLICY_VERSION,
    }
    payload.update(overrides)
    return payload


def manifest(**overrides):
    payload = {
        "schema": EVIDENCE_MANIFEST_SCHEMA,
        "manifest_id": "manifest-1",
        "generated_at": "2026-06-17T05:05:00Z",
        "policy_version": EVIDENCE_POLICY_VERSION,
        "artifact_count": 1,
        "artifact_hashes": {"artifact-1": "a" * 64},
        "manifest_hash": "m" * 64,
        "previous_manifest_hash": "p" * 64,
        "signature_hash": "s" * 64,
        "timestamp_token_hash": "t" * 64,
        "verification_status": "VERIFIED",
        "fail_closed": False,
        "reason_codes": [],
    }
    payload.update(overrides)
    return payload


def test_valid_artifact_and_manifest_contracts():
    assert validate_artifact_record(artifact()).valid is True
    assert validate_evidence_manifest(manifest()).valid is True


def test_missing_manifest_fields_block():
    result = validate_evidence_manifest(manifest(manifest_hash="", policy_version=""))

    assert result.valid is False
    assert "EVIDENCE_MANIFEST_MANIFEST_HASH_MISSING" in result.reason_codes
    assert "EVIDENCE_MANIFEST_POLICY_VERSION_MISSING" in result.reason_codes


def test_unknown_verification_status_blocks():
    result = validate_evidence_manifest(manifest(verification_status="AUTO_VERIFIED"))

    assert result.valid is False
    assert "EVIDENCE_VERIFICATION_STATUS_UNKNOWN:AUTO_VERIFIED" in result.reason_codes


def test_missing_artifact_hash_schema_and_policy_block():
    result = validate_artifact_record(artifact(artifact_hash="", artifact_schema="", policy_version=""))

    assert result.valid is False
    assert "EVIDENCE_ARTIFACT_ARTIFACT_HASH_MISSING" in result.reason_codes
    assert "EVIDENCE_ARTIFACT_ARTIFACT_SCHEMA_MISSING" in result.reason_codes
    assert "EVIDENCE_ARTIFACT_POLICY_VERSION_MISSING" in result.reason_codes
