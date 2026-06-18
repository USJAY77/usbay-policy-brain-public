from __future__ import annotations

import pytest

from governance.document_library_review import evaluate_document_library_review


pytestmark = pytest.mark.governance


def library(**overrides):
    payload = {"auto_rewrite": False, "auto_publish": False, "auto_delete": False, "sensitive_data_retention": False}
    payload.update(overrides)
    return payload


def test_review_approved_with_human_approval():
    result = evaluate_document_library_review(library(), human_approval={"approved": True})

    assert result["document_library_review_status"] == "APPROVED"
    assert result["document_publish_enabled"] is False


def test_review_without_human_approval_blocks():
    result = evaluate_document_library_review(library(), human_approval=None)

    assert "NO_HUMAN_APPROVAL" in result["reason_codes"]


def test_review_blocks_auto_document_actions():
    result = evaluate_document_library_review(
        library(auto_rewrite=True, auto_publish=True, auto_delete=True),
        human_approval={"approved": True},
    )

    assert "AUTO_REWRITE_FORBIDDEN" in result["reason_codes"]
    assert "AUTO_PUBLISH_FORBIDDEN" in result["reason_codes"]
    assert "AUTO_DELETE_FORBIDDEN" in result["reason_codes"]


def test_review_blocks_sensitive_retention():
    result = evaluate_document_library_review(library(sensitive_data_retention=True), human_approval={"approved": True})

    assert "SENSITIVE_DATA_RETENTION_FORBIDDEN" in result["reason_codes"]
