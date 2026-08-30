from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.evidence_manifest import build_artifact_record, build_evidence_manifest, canonical_manifest_hash
from governance.evidence_signing import build_evidence_signature
from governance.evidence_timestamp import build_evidence_timestamp
from governance.evidence_verifier import empty_evidence_trust_dashboard_state, verify_evidence_trust


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 6, 0, tzinfo=timezone.utc)
PAYLOAD = {"decision": "VERIFIED", "raw": "redacted"}


def artifact(payload=PAYLOAD, **overrides):
    record = build_artifact_record(
        artifact_id="artifact-1",
        artifact_path="governance/evidence/artifact-1.json",
        artifact_schema="usbay.example.v1",
        artifact_payload=payload,
        created_at="2026-06-17T05:00:00Z",
        source_pb="PB-EVIDENCE",
    )
    record.update(overrides)
    return record


def bundle(record=None, payload=PAYLOAD, previous="p" * 64):
    manifest = build_evidence_manifest([artifact() if record is None else record], generated_at="2026-06-17T05:05:00Z", previous_manifest_hash=previous)
    signature = build_evidence_signature(
        manifest_hash=manifest["manifest_hash"],
        signer_id="auditor-1",
        signer_role="USBAY_AUDITOR",
        created_at="2026-06-17T05:06:00Z",
    )
    timestamp = build_evidence_timestamp(
        manifest_hash=manifest["manifest_hash"],
        timestamp_authority="USBAY_LOCAL_RFC3161_PLACEHOLDER",
        issued_at="2026-06-17T05:10:00Z",
    )
    manifest["signature_hash"] = signature["signature_hash"]
    manifest["timestamp_token_hash"] = timestamp["timestamp_token_hash"]
    return manifest, {"artifact-1": payload}, signature, timestamp


def verify(manifest, payloads, signature, timestamp, previous="p" * 64):
    return verify_evidence_trust(
        manifest=manifest,
        artifact_payloads=payloads,
        signature=signature,
        timestamp=timestamp,
        expected_previous_manifest_hash=previous,
        now=NOW,
    )


def test_valid_manifest_verifies():
    result = verify(*bundle())

    assert result.verification_status == "VERIFIED"
    assert result.reason_codes == ()


def test_missing_artifact_blocks():
    manifest, _payloads, signature, timestamp = bundle()
    result = verify(manifest, {}, signature, timestamp)

    assert result.verification_status == "MISSING_ARTIFACT"
    assert "EVIDENCE_MISSING_ARTIFACT:artifact-1" in result.reason_codes


def test_hash_mismatch_tampers():
    result = verify(*bundle(payload={"changed": True}))

    assert result.verification_status == "TAMPERED"
    assert "EVIDENCE_ARTIFACT_HASH_MISMATCH:artifact-1" in result.reason_codes


def test_manifest_hash_mismatch_tampers():
    manifest, payloads, signature, timestamp = bundle()
    manifest["manifest_hash"] = "0" * 64

    result = verify(manifest, payloads, signature, timestamp)

    assert result.verification_status == "TAMPERED"
    assert "EVIDENCE_MANIFEST_HASH_MISMATCH" in result.reason_codes


def test_previous_manifest_mismatch_blocks():
    result = verify(*bundle(), previous="other")

    assert result.verification_status == "BLOCKED"
    assert "EVIDENCE_PREVIOUS_MANIFEST_MISMATCH" in result.reason_codes


def test_missing_signature_blocks():
    manifest, payloads, _signature, timestamp = bundle()
    result = verify(manifest, payloads, None, timestamp)

    assert result.verification_status == "MISSING_SIGNATURE"
    assert "EVIDENCE_SIGNATURE_MISSING" in result.reason_codes


def test_invalid_signature_blocks_as_tamper():
    manifest, payloads, signature, timestamp = bundle()
    signature["signature_hash"] = "0" * 64
    result = verify(manifest, payloads, signature, timestamp)

    assert result.verification_status == "TAMPERED"
    assert "EVIDENCE_SIGNATURE_INVALID" in result.reason_codes


def test_missing_timestamp_blocks():
    manifest, payloads, signature, _timestamp = bundle()
    result = verify(manifest, payloads, signature, None)

    assert result.verification_status == "MISSING_TIMESTAMP"
    assert "EVIDENCE_TIMESTAMP_MISSING" in result.reason_codes


def test_policy_and_schema_mismatch_block():
    record = artifact(policy_version="other", schema="wrong")
    manifest, payloads, signature, timestamp = bundle(record=record)

    result = verify(manifest, payloads, signature, timestamp)

    assert result.verification_status in {"POLICY_MISMATCH", "TAMPERED"}
    assert "EVIDENCE_ARTIFACT_SCHEMA_INVALID" in result.reason_codes
    assert "EVIDENCE_ARTIFACT_POLICY_MISMATCH:artifact-1" in result.reason_codes


def test_empty_dashboard_state_is_fail_closed():
    state = empty_evidence_trust_dashboard_state()

    assert state["verification_status"] == "MISSING_SIGNATURE"
    assert state["signature_status"] == "BLOCKED"
    assert state["timestamp_status"] == "BLOCKED"
    assert state["timestamp_integration_status"] == "NOT_IMPLEMENTED"
    assert state["auto_verified"] is False
    assert state["auto_signed"] is False
    assert state["auto_timestamped"] is False
    assert state["auto_repaired"] is False
