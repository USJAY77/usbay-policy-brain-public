from __future__ import annotations

from typing import Any

from governance.document_contracts import validate_document


TRACKED_DOCUMENT_TYPES = (
    "POLICY",
    "STANDARD",
    "PROCEDURE",
    "ROADMAP",
    "TARIFF_CARD",
    "CONTRACT",
    "APPENDIX",
    "GOVERNANCE_REPORT",
    "EVIDENCE_REPORT",
)


class DocumentRegistry:
    def __init__(self, documents: list[dict[str, Any]] | None = None):
        self._documents = tuple(document for document in documents or [] if isinstance(document, dict))

    def register_document(self, document: dict[str, Any]) -> dict[str, Any]:
        validation = validate_document(document)
        return {
            "registration_status": "REGISTERED_READ_ONLY" if validation.valid else validation.status,
            "document": dict(document) if isinstance(document, dict) else {},
            "reason_codes": list(validation.reason_codes),
            "read_only": True,
            "modify_enabled": False,
            "publish_enabled": False,
            "delete_enabled": False,
            "auto_published": False,
            "auto_approved": False,
            "auto_archived": False,
            "auto_rewritten": False,
        }

    def get_document(self, document_id: str) -> list[dict[str, Any]]:
        return [dict(document) for document in self._documents if document.get("document_id") == document_id]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        for document in self._documents:
            validation = validate_document(document)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
        return {
            "document_registry_status": "BLOCKED" if reasons else ("VALID" if self._documents else "BLOCKED"),
            "document_count": len(self._documents),
            "document_review_status": "BLOCKED",
            "document_version_status": "BLOCKED",
            "document_classification_status": "BLOCKED",
            "document_lineage_status": "BLOCKED",
            "document_reason_codes": sorted(set(reasons)) or ([] if self._documents else ["DOCUMENT_REGISTRY_EMPTY"]),
            "read_only": True,
            "auto_approved": False,
            "auto_published": False,
            "auto_archived": False,
            "auto_replaced": False,
            "auto_rewritten": False,
        }


def empty_document_dashboard_state() -> dict[str, Any]:
    return DocumentRegistry().summary()
