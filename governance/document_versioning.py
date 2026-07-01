from __future__ import annotations

from typing import Any

from governance.document_contracts import validate_document


def register_document_version(document: dict[str, Any] | None, existing_versions: list[str] | None = None, parent_version: str = "") -> dict[str, Any]:
    validation = validate_document(document)
    reasons = list(validation.reason_codes)
    version = str(document.get("version", "") if isinstance(document, dict) else "")
    existing = set(str(item) for item in existing_versions or [])
    if not version:
        reasons.append("DOCUMENT_VERSION_MISSING")
    if version in existing:
        reasons.append("DOCUMENT_DUPLICATE_VERSION")
    if parent_version and parent_version not in existing:
        reasons.append("DOCUMENT_PARENT_VERSION_UNKNOWN")
    if not isinstance(document, dict) or not str(document.get("lineage_hash", "")).strip():
        reasons.append("DOCUMENT_LINEAGE_MISSING")
    return {
        "document_version_status": "BLOCKED" if reasons else "VALID",
        "version": version,
        "parent_version": str(parent_version),
        "reason_codes": sorted(set(reasons)),
        "auto_replaced": False,
        "auto_rewritten": False,
    }


def compare_document_versions(current: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    current_version = str(current.get("version", ""))
    candidate_version = str(candidate.get("version", ""))
    return {
        "comparison_status": "REVIEW_REQUIRED" if current_version != candidate_version else "VALID",
        "current_version": current_version,
        "candidate_version": candidate_version,
        "superseded": current_version != candidate_version,
        "auto_replaced": False,
        "auto_rewritten": False,
    }
