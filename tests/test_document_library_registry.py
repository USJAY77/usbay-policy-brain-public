from __future__ import annotations

import pytest

from governance.document_library_contracts import build_document_library_record
from governance.document_library_registry import DocumentLibraryRegistry, evaluate_document_library_registry


pytestmark = pytest.mark.governance


def library(**overrides):
    payload = {
        "library_id": "lib-1",
        "workspace_id": "ws-1",
        "tenant_id": "tenant-1",
        "document_id": "doc-1",
        "document_version": "v1",
        "library_state": "ACTIVE",
        "policy_hash": "p" * 64,
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "document_hash": "d" * 64,
        "lineage_hash": "l" * 64,
        "human_approval": True,
        "created_at": "2026-06-18T00:00:00Z",
        "reason_codes": [],
        "fail_closed": False,
    }
    payload.update(overrides)
    return build_document_library_record(**payload)


def test_registry_counts_valid_libraries():
    result = DocumentLibraryRegistry([library()]).summary()

    assert result["document_library_registry_status"] == "VALID"
    assert result["document_library_count"] == 1
    assert result["connector_write_enabled"] is False


def test_unknown_library_blocks_registry():
    result = evaluate_document_library_registry(None)

    assert result["document_library_registry_status"] == "BLOCKED"
    assert "UNKNOWN_DOCUMENT_LIBRARY" in result["document_library_reason_codes"]


def test_duplicate_without_version_blocks():
    first = library(document_version="")
    second = library(library_id="lib-2", document_version="")

    result = DocumentLibraryRegistry([first, second]).summary()

    assert result["document_library_registry_status"] == "BLOCKED"
    assert "DUPLICATE_WITHOUT_VERSION" in result["document_library_reason_codes"]
