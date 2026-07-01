from __future__ import annotations

import pytest

from governance.document_contracts import build_document, validate_document


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


def test_valid_document():
    validation = validate_document(document())

    assert validation.valid is True
    assert validation.status == "VALID"


@pytest.mark.parametrize("field", ["document_owner", "tenant_id", "policy_hash", "audit_hash", "lineage_hash"])
def test_missing_required_link_blocks(field):
    record = document()
    record[field] = ""

    validation = validate_document(record)

    assert validation.valid is False


def test_unknown_classification_blocks():
    validation = validate_document(document(document_classification="SECRET"))

    assert validation.status == "BLOCKED"
    assert "DOCUMENT_CLASSIFICATION_UNKNOWN:SECRET" in validation.reason_codes


def test_hash_mismatch_detects_tamper():
    record = document()
    record["document_title"] = "Changed"

    validation = validate_document(record)

    assert validation.status == "TAMPER_DETECTED"
