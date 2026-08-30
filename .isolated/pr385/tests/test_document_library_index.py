from __future__ import annotations

import pytest

from governance.document_library_index import evaluate_document_library_index


pytestmark = pytest.mark.governance


def library(**overrides):
    payload = {
        "library_id": "lib-1",
        "workspace_id": "ws-1",
        "tenant_id": "tenant-1",
        "document_hash": "d" * 64,
        "lineage_hash": "l" * 64,
        "shared_default_library": False,
        "auto_classification": False,
        "raw_payload_logging": False,
    }
    payload.update(overrides)
    return payload


def test_valid_index_visibility():
    result = evaluate_document_library_index(library())

    assert result["document_library_index_status"] == "INDEXED"
    assert result["auto_classification"] is False


def test_missing_document_hash_and_lineage_block():
    result = evaluate_document_library_index(library(document_hash="", lineage_hash=""))

    assert "MISSING_DOCUMENT_HASH" in result["reason_codes"]
    assert "MISSING_LINEAGE" in result["reason_codes"]


def test_shared_default_library_blocks():
    result = evaluate_document_library_index(library(shared_default_library=True))

    assert "SHARED_DEFAULT_LIBRARY_FORBIDDEN" in result["reason_codes"]


def test_auto_classification_and_raw_payload_logging_block():
    result = evaluate_document_library_index(library(auto_classification=True, raw_payload_logging=True))

    assert "AUTO_CLASSIFICATION_FORBIDDEN" in result["reason_codes"]
    assert "RAW_PAYLOAD_LOGGING_FORBIDDEN" in result["reason_codes"]
