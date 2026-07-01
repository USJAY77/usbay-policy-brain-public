from __future__ import annotations

from typing import Any


def evaluate_document_library_index(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_DOCUMENT_LIBRARY")
    else:
        if not str(record.get("workspace_id", "")).strip():
            reasons.append("MISSING_WORKSPACE")
        if not str(record.get("tenant_id", "")).strip():
            reasons.append("MISSING_TENANT")
        if not str(record.get("document_hash", "")).strip():
            reasons.append("MISSING_DOCUMENT_HASH")
        if not str(record.get("lineage_hash", "")).strip():
            reasons.append("MISSING_LINEAGE")
        if record.get("shared_default_library") is True or str(record.get("library_id", "")).lower() in {"default", "shared"}:
            reasons.append("SHARED_DEFAULT_LIBRARY_FORBIDDEN")
        if record.get("auto_classification") is True:
            reasons.append("AUTO_CLASSIFICATION_FORBIDDEN")
        if record.get("raw_payload_logging") is True:
            reasons.append("RAW_PAYLOAD_LOGGING_FORBIDDEN")
    status = "INDEXED" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.document_library.index.v1",
        "document_library_index_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "index_write_enabled": False,
        "auto_classification": False,
        "raw_payload_logging": False,
        "connector_write_enabled": False,
    }
