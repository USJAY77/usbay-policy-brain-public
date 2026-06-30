from __future__ import annotations

from typing import Any

from governance.document_library_contracts import validate_document_library


class DocumentLibraryRegistry:
    def __init__(self, records: list[dict[str, Any]] | None = None):
        self._records = tuple(record for record in records or [] if isinstance(record, dict))

    def get_library(self, library_id: str) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records if record.get("library_id") == library_id]

    def list_libraries(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        seen: set[tuple[str, str, str]] = set()
        for record in self._records:
            validation = validate_document_library(record)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
            key = (str(record.get("workspace_id", "")), str(record.get("tenant_id", "")), str(record.get("document_id", "")))
            version = str(record.get("document_version", ""))
            if key in seen and not version:
                reasons.append("DUPLICATE_WITHOUT_VERSION")
            seen.add(key)
        status = "VALID" if self._records and not reasons else "BLOCKED"
        return {
            "document_library_registry_status": status,
            "document_library_count": len(self._records),
            "document_library_reason_codes": sorted(set(reasons)) or ([] if self._records else ["UNKNOWN_DOCUMENT_LIBRARY"]),
            "read_only": True,
            "register_enabled": False,
            "update_enabled": False,
            "delete_enabled": False,
            "connector_write_enabled": False,
        }


def evaluate_document_library_registry(records: list[dict[str, Any]] | None) -> dict[str, Any]:
    if not isinstance(records, list):
        return DocumentLibraryRegistry().summary()
    return DocumentLibraryRegistry(records).summary()
