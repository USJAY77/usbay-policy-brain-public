from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.evidence_timestamp import TIMESTAMP_INTEGRATION_STATUS, build_evidence_timestamp, validate_evidence_timestamp


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 6, 0, tzinfo=timezone.utc)


def test_valid_timestamp_placeholder_verifies_contractually():
    timestamp = build_evidence_timestamp(
        manifest_hash="m" * 64,
        timestamp_authority="USBAY_LOCAL_RFC3161_PLACEHOLDER",
        issued_at="2026-06-17T05:10:00Z",
    )

    valid, reasons = validate_evidence_timestamp(
        timestamp,
        manifest_hash="m" * 64,
        artifact_created_at_values=["2026-06-17T05:00:00Z"],
        now=NOW,
    )

    assert valid is True
    assert reasons == ()
    assert timestamp["timestamp_integration_status"] == TIMESTAMP_INTEGRATION_STATUS


def test_missing_timestamp_blocks():
    valid, reasons = validate_evidence_timestamp(None, manifest_hash="m" * 64, artifact_created_at_values=[], now=NOW)

    assert valid is False
    assert "EVIDENCE_TIMESTAMP_MISSING" in reasons


def test_future_timestamp_blocks():
    timestamp = build_evidence_timestamp(
        manifest_hash="m" * 64,
        timestamp_authority="USBAY_LOCAL_RFC3161_PLACEHOLDER",
        issued_at="2026-06-18T05:10:00Z",
    )

    valid, reasons = validate_evidence_timestamp(timestamp, manifest_hash="m" * 64, artifact_created_at_values=[], now=NOW)

    assert valid is False
    assert "EVIDENCE_TIMESTAMP_FUTURE" in reasons


def test_timestamp_before_artifact_creation_blocks():
    timestamp = build_evidence_timestamp(
        manifest_hash="m" * 64,
        timestamp_authority="USBAY_LOCAL_RFC3161_PLACEHOLDER",
        issued_at="2026-06-17T04:00:00Z",
    )

    valid, reasons = validate_evidence_timestamp(
        timestamp,
        manifest_hash="m" * 64,
        artifact_created_at_values=["2026-06-17T05:00:00Z"],
        now=NOW,
    )

    assert valid is False
    assert "EVIDENCE_TIMESTAMP_BEFORE_ARTIFACT" in reasons


def test_unknown_timestamp_authority_blocks():
    timestamp = build_evidence_timestamp(
        manifest_hash="m" * 64,
        timestamp_authority="EXTERNAL_TSA_NOT_APPROVED",
        issued_at="2026-06-17T05:10:00Z",
    )

    valid, reasons = validate_evidence_timestamp(timestamp, manifest_hash="m" * 64, artifact_created_at_values=[], now=NOW)

    assert valid is False
    assert "EVIDENCE_TIMESTAMP_AUTHORITY_UNKNOWN" in reasons
