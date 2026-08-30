from __future__ import annotations

import pytest

from governance.document_contracts import build_document
from governance.document_versioning import compare_document_versions, register_document_version


pytestmark = pytest.mark.governance


def document(version="v1", **overrides):
    payload = {
        "document_id": "doc-1",
        "document_title": "Governance Policy",
        "document_type": "POLICY",
        "document_classification": "INTERNAL",
        "document_owner": "owner-1",
        "tenant_id": "tenant-1",
        "version": version,
        "status": "DRAFT",
        "created_at": "2026-06-18T08:00:00Z",
        "updated_at": "2026-06-18T08:00:00Z",
        "policy_hash": "p" * 64,
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
    }
    payload.update(overrides)
    return build_document(**payload)


def test_valid_version_registration():
    result = register_document_version(document(), existing_versions=[])

    assert result["document_version_status"] == "VALID"


def test_duplicate_version_blocks():
    result = register_document_version(document(), existing_versions=["v1"])

    assert result["document_version_status"] == "BLOCKED"
    assert "DOCUMENT_DUPLICATE_VERSION" in result["reason_codes"]


def test_unknown_parent_version_blocks():
    result = register_document_version(document("v2"), existing_versions=["v1"], parent_version="v0")

    assert "DOCUMENT_PARENT_VERSION_UNKNOWN" in result["reason_codes"]


def test_version_comparison_detects_superseded_without_auto_replace():
    result = compare_document_versions(document("v1"), document("v2"))

    assert result["comparison_status"] == "REVIEW_REQUIRED"
    assert result["superseded"] is True
    assert result["auto_replaced"] is False
    assert result["auto_rewritten"] is False
