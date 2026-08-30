from __future__ import annotations

import pytest

from governance.evidence_contracts import EVIDENCE_POLICY_VERSION
from governance.evidence_manifest import build_artifact_record, build_evidence_manifest, canonical_manifest_hash


pytestmark = pytest.mark.governance


def artifact(artifact_id="artifact-1", payload=None, **overrides):
    record = build_artifact_record(
        artifact_id=artifact_id,
        artifact_path=f"governance/evidence/{artifact_id}.json",
        artifact_schema="usbay.example.v1",
        artifact_payload={"value": artifact_id} if payload is None else payload,
        created_at="2026-06-17T05:00:00Z",
        source_pb="PB-EVIDENCE",
    )
    record.update(overrides)
    return record


def test_valid_manifest_builds_hash_only_artifacts():
    manifest = build_evidence_manifest(
        [artifact()],
        generated_at="2026-06-17T05:05:00Z",
        previous_manifest_hash="p" * 64,
        signature_hash="s" * 64,
        timestamp_token_hash="t" * 64,
    )

    assert manifest["verification_status"] == "VERIFIED"
    assert manifest["manifest_hash"] == canonical_manifest_hash(manifest)
    assert manifest["artifact_count"] == 1
    assert "artifact_payload" not in str(manifest)


def test_missing_artifact_list_blocks():
    manifest = build_evidence_manifest(None, generated_at="2026-06-17T05:05:00Z")

    assert manifest["verification_status"] == "BLOCKED"
    assert "EVIDENCE_ARTIFACT_LIST_MISSING" in manifest["reason_codes"]


def test_missing_hash_blocks():
    manifest = build_evidence_manifest([artifact(artifact_hash="")], generated_at="2026-06-17T05:05:00Z")

    assert manifest["fail_closed"] is True
    assert "EVIDENCE_ARTIFACT_ARTIFACT_HASH_MISSING" in manifest["reason_codes"]


def test_duplicate_artifact_id_blocks():
    manifest = build_evidence_manifest([artifact("same"), artifact("same")], generated_at="2026-06-17T05:05:00Z")

    assert manifest["fail_closed"] is True
    assert "EVIDENCE_DUPLICATE_ARTIFACT_ID:same" in manifest["reason_codes"]


def test_policy_mismatch_metadata_blocks():
    manifest = build_evidence_manifest(
        [artifact(policy_version="other")],
        generated_at="2026-06-17T05:05:00Z",
        policy_version=EVIDENCE_POLICY_VERSION,
        previous_manifest_hash="p" * 64,
        signature_hash="s" * 64,
        timestamp_token_hash="t" * 64,
    )

    assert manifest["fail_closed"] is False
    assert manifest["artifacts"][0]["policy_version"] == "other"


def test_no_raw_secret_or_screenshot_payload_logging():
    manifest = build_evidence_manifest(
        [artifact(artifact_path="governance/evidence/redacted.json", secret_reference="raw_screenshot_payload")],
        generated_at="2026-06-17T05:05:00Z",
    )

    assert manifest["fail_closed"] is True
    assert any(code.startswith("EVIDENCE_FORBIDDEN_METADATA") for code in manifest["reason_codes"])
