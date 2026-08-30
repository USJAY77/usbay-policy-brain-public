from __future__ import annotations

from typing import Any

from governance.document_contracts import ALLOWED_DOCUMENT_CLASSIFICATIONS, validate_document


def evaluate_document_classification(document: dict[str, Any] | None) -> dict[str, Any]:
    validation = validate_document(document)
    reasons = list(validation.reason_codes)
    safe = document if isinstance(document, dict) else {}
    if str(safe.get("document_classification", "")) not in ALLOWED_DOCUMENT_CLASSIFICATIONS:
        reasons.append("DOCUMENT_CLASSIFICATION_INVALID")
    if not str(safe.get("document_owner", "")).strip():
        reasons.append("DOCUMENT_OWNER_MISSING")
    if not str(safe.get("tenant_id", "")).strip():
        reasons.append("DOCUMENT_TENANT_MISSING")
    if not str(safe.get("policy_hash", "")).strip() or not str(safe.get("policy_version", "")).strip():
        reasons.append("DOCUMENT_POLICY_LINKAGE_MISSING")
    if not str(safe.get("audit_hash", "")).strip():
        reasons.append("DOCUMENT_AUDIT_LINKAGE_MISSING")
    if not str(safe.get("lineage_hash", "")).strip():
        reasons.append("DOCUMENT_LINEAGE_LINKAGE_MISSING")
    return {
        "document_classification_status": "BLOCKED" if reasons else "VALID",
        "document_classification": str(safe.get("document_classification", "")),
        "reason_codes": sorted(set(reasons)),
        "auto_approved": False,
        "auto_published": False,
        "auto_rewritten": False,
    }
