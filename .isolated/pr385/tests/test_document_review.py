from __future__ import annotations

import pytest

from governance.document_contracts import build_document
from governance.document_review import evaluate_document_review


pytestmark = pytest.mark.governance


def document(**overrides):
    payload = {
        "document_id": "doc-1",
        "document_title": "Governance Policy",
        "document_type": "POLICY",
        "document_classification": "INTERNAL",
        "document_owner": "owner-1",
        "tenant_id": "tenant-1",
        "version": "v1",
        "status": "DRAFT",
        "created_at": "2026-06-18T08:00:00Z",
        "updated_at": "2026-06-18T08:00:00Z",
        "policy_hash": "p" * 64,
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
    }
    payload.update(overrides)
    return build_document(**payload)


def test_valid_review():
    result = evaluate_document_review(
        document=document(),
        review_state="REVIEW_REQUIRED",
        human_reviewer="reviewer-1",
        audit_record={"audit_hash": "a" * 64},
        policy_version="policy-v1",
        lineage_record={"lineage_hash": "l" * 64},
    )

    assert result["document_review_status"] == "VALID"
    assert result["auto_approved"] is False
    assert result["auto_published"] is False


def test_missing_reviewer_blocks():
    result = evaluate_document_review(
        document=document(),
        review_state="REVIEW_REQUIRED",
        human_reviewer="",
        audit_record={"audit_hash": "a" * 64},
        policy_version="policy-v1",
        lineage_record={"lineage_hash": "l" * 64},
    )

    assert result["document_review_status"] == "BLOCKED"
    assert "DOCUMENT_HUMAN_REVIEWER_MISSING" in result["reason_codes"]


def test_missing_audit_and_lineage_block():
    result = evaluate_document_review(
        document=document(),
        review_state="REVIEW_REQUIRED",
        human_reviewer="reviewer-1",
        audit_record=None,
        policy_version="policy-v1",
        lineage_record=None,
    )

    assert "DOCUMENT_REVIEW_AUDIT_RECORD_MISSING" in result["reason_codes"]
    assert "DOCUMENT_REVIEW_LINEAGE_RECORD_MISSING" in result["reason_codes"]
    assert result["auto_archived"] is False
