from __future__ import annotations

import pytest

from governance.document_classification import evaluate_document_classification
from governance.document_contracts import build_document


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


def test_valid_classification():
    result = evaluate_document_classification(document())

    assert result["document_classification_status"] == "VALID"
    assert result["auto_published"] is False


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("document_owner", "DOCUMENT_OWNER_MISSING"),
        ("tenant_id", "DOCUMENT_TENANT_MISSING"),
        ("policy_hash", "DOCUMENT_POLICY_LINKAGE_MISSING"),
        ("audit_hash", "DOCUMENT_AUDIT_LINKAGE_MISSING"),
        ("lineage_hash", "DOCUMENT_LINEAGE_LINKAGE_MISSING"),
    ],
)
def test_missing_classification_links_block(field, reason):
    record = document()
    record[field] = ""

    result = evaluate_document_classification(record)

    assert result["document_classification_status"] == "BLOCKED"
    assert reason in result["reason_codes"]


def test_unknown_classification_blocks():
    result = evaluate_document_classification(document(document_classification="UNKNOWN"))

    assert result["document_classification_status"] == "BLOCKED"
    assert "DOCUMENT_CLASSIFICATION_INVALID" in result["reason_codes"]
    assert result["auto_rewritten"] is False
