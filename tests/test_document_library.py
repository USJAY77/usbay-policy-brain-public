from __future__ import annotations

import pytest

from governance.document_library import empty_document_library_dashboard_state, evaluate_document_library
from governance.document_library_contracts import build_document_library_record
from governance.document_library_registry import DocumentLibraryRegistry


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


def test_document_library_active_when_controls_pass():
    record = library()
    result = evaluate_document_library(
        record=record,
        registry=DocumentLibraryRegistry([record]),
        requesting_tenant_id="tenant-1",
        human_approval={"approved": True},
    )

    assert result["document_library_status"] == "ACTIVE"
    assert result["document_library_count"] == 1
    assert result["document_delete_enabled"] is False


def test_document_library_blocks_cross_tenant_access():
    record = library()
    result = evaluate_document_library(
        record=record,
        registry=DocumentLibraryRegistry([record]),
        requesting_tenant_id="tenant-2",
        human_approval={"approved": True},
    )

    assert result["document_library_status"] == "BLOCKED"
    assert "CROSS_TENANT_LIBRARY_ACCESS" in result["document_library_reason_codes"]


def test_document_library_blocks_missing_document_hash():
    record = library(document_hash="")
    result = evaluate_document_library(
        record=record,
        registry=DocumentLibraryRegistry([record]),
        requesting_tenant_id="tenant-1",
        human_approval={"approved": True},
    )

    assert "MISSING_DOCUMENT_HASH" in result["document_library_reason_codes"]


def test_empty_document_library_dashboard_state_is_fail_closed():
    state = empty_document_library_dashboard_state()

    assert state["document_library_status"] == "BLOCKED"
    assert state["document_library_count"] == 0
    assert state["document_rewrite_enabled"] is False
    assert state["auto_classification"] is False
    assert state["raw_payload_logging"] is False
