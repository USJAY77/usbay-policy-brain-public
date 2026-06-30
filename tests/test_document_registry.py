from __future__ import annotations

import pytest

from governance.document_contracts import build_document
from governance.document_registry import DocumentRegistry, empty_document_dashboard_state


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


def test_read_only_registration():
    registry = DocumentRegistry([document()])
    result = registry.register_document(document())

    assert result["registration_status"] == "REGISTERED_READ_ONLY"
    assert result["modify_enabled"] is False
    assert result["publish_enabled"] is False
    assert result["delete_enabled"] is False


def test_summary_counts_documents():
    summary = DocumentRegistry([document()]).summary()

    assert summary["document_registry_status"] == "VALID"
    assert summary["document_count"] == 1
    assert summary["auto_published"] is False


def test_empty_dashboard_blocks():
    state = empty_document_dashboard_state()

    assert state["document_registry_status"] == "BLOCKED"
    assert state["document_count"] == 0
    assert state["auto_approved"] is False
    assert state["auto_rewritten"] is False
