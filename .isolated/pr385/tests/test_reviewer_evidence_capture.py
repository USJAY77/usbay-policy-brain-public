from __future__ import annotations

import pytest

from governance.reviewer_evidence_capture import (
    REVIEWER_EVIDENCE_CAPTURE_VERSION,
    ApprovalStatus,
    ReviewerEvidence,
    reviewer_evidence_capture_schema,
    sha256_review_evidence,
    validate_reviewer_evidence,
)


pytestmark = pytest.mark.governance


def _review() -> dict[str, str]:
    return ReviewerEvidence(
        reviewer_identity="human-reviewer",
        timestamp="2026-06-14T00:00:00Z",
        approval_status=ApprovalStatus.APPROVED,
        review_evidence_hash=sha256_review_evidence({"review": "approved"}),
    ).to_dict()


def test_reviewer_evidence_schema_declares_required_hash_only_fields() -> None:
    schema = reviewer_evidence_capture_schema()

    assert schema["title"] == "USBAY Reviewer Evidence Capture"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["contract_version"]["const"] == REVIEWER_EVIDENCE_CAPTURE_VERSION
    assert schema["properties"]["approval_status"]["enum"] == [status.value for status in ApprovalStatus]
    assert "review_evidence_hash" in schema["required"]


def test_valid_reviewer_evidence_records() -> None:
    result = validate_reviewer_evidence(_review())

    assert result["decision"] == "RECORDED"
    assert result["gaps"] == []


def test_missing_reviewer_identity_fails_closed() -> None:
    payload = _review()
    payload["reviewer_identity"] = ""

    result = validate_reviewer_evidence(payload)

    assert result["decision"] == "FAIL_CLOSED"
    assert "REVIEWER_EVIDENCE_REVIEWER_IDENTITY_MISSING" in result["gaps"]


def test_invalid_approval_status_fails_closed() -> None:
    payload = _review()
    payload["approval_status"] = "AUTO_APPROVED"

    result = validate_reviewer_evidence(payload)

    assert result["decision"] == "FAIL_CLOSED"
    assert "REVIEWER_EVIDENCE_APPROVAL_STATUS_INVALID" in result["gaps"]


def test_raw_or_missing_review_evidence_hash_fails_closed() -> None:
    payload = _review()
    payload["review_evidence_hash"] = "approved by human"

    result = validate_reviewer_evidence(payload)

    assert result["decision"] == "FAIL_CLOSED"
    assert "REVIEWER_EVIDENCE_HASH_INVALID" in result["gaps"]
