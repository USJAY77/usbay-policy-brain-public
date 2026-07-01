from __future__ import annotations

import pytest

from governance.document_library_contracts import (
    FAIL_CLOSED_REASON_CODES,
    build_document_library_record,
    validate_document_library,
)


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


def test_valid_document_library_contract():
    result = validate_document_library(library())

    assert result.valid is True
    assert result.status == "ACTIVE"


def test_missing_workspace_tenant_and_hashes_block():
    result = validate_document_library(
        library(workspace_id="", tenant_id="", policy_hash="", audit_hash="", evidence_hash="", document_hash="", lineage_hash="")
    )

    assert "MISSING_WORKSPACE" in result.reason_codes
    assert "MISSING_TENANT" in result.reason_codes
    assert "MISSING_POLICY" in result.reason_codes
    assert "MISSING_AUDIT" in result.reason_codes
    assert "MISSING_EVIDENCE" in result.reason_codes
    assert "MISSING_DOCUMENT_HASH" in result.reason_codes
    assert "MISSING_LINEAGE" in result.reason_codes


def test_document_library_without_human_approval_blocks():
    result = validate_document_library(library(human_approval=False))

    assert "NO_HUMAN_APPROVAL" in result.reason_codes


def test_auto_actions_and_connector_write_block():
    record = library()
    record.update({"auto_classification": True, "auto_rewrite": True, "auto_publish": True, "auto_delete": True, "connector_write": True})

    result = validate_document_library(record)

    assert "AUTO_CLASSIFICATION_FORBIDDEN" in result.reason_codes
    assert "AUTO_REWRITE_FORBIDDEN" in result.reason_codes
    assert "AUTO_PUBLISH_FORBIDDEN" in result.reason_codes
    assert "AUTO_DELETE_FORBIDDEN" in result.reason_codes
    assert "CONNECTOR_WRITE_FORBIDDEN" in result.reason_codes


def test_raw_payload_and_sensitive_retention_block():
    record = library()
    record.update({"raw_payload_logging": True, "note": "credential private_key"})

    result = validate_document_library(record)

    assert "RAW_PAYLOAD_LOGGING_FORBIDDEN" in result.reason_codes
    assert "SENSITIVE_DATA_RETENTION_FORBIDDEN" in result.reason_codes


def test_fail_closed_reason_code_registry_contains_required_codes():
    assert "UNKNOWN_DOCUMENT_LIBRARY" in FAIL_CLOSED_REASON_CODES
    assert "SENSITIVE_DATA_RETENTION_FORBIDDEN" in FAIL_CLOSED_REASON_CODES
