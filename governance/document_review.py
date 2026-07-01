from __future__ import annotations

from typing import Any

from governance.document_contracts import validate_document


DOCUMENT_REVIEW_STATES = frozenset({"DRAFT", "REVIEW_REQUIRED", "APPROVED", "SUPERSEDED", "ARCHIVED", "BLOCKED"})


def evaluate_document_review(
    *,
    document: dict[str, Any] | None,
    review_state: str,
    human_reviewer: str,
    audit_record: dict[str, Any] | None,
    policy_version: str,
    lineage_record: dict[str, Any] | None,
) -> dict[str, Any]:
    validation = validate_document(document)
    reasons = list(validation.reason_codes)
    if review_state not in DOCUMENT_REVIEW_STATES:
        reasons.append(f"DOCUMENT_REVIEW_STATE_UNKNOWN:{review_state or 'MISSING'}")
    if not str(human_reviewer).strip():
        reasons.append("DOCUMENT_HUMAN_REVIEWER_MISSING")
    if not isinstance(audit_record, dict) or not str(audit_record.get("audit_hash", "")).strip():
        reasons.append("DOCUMENT_REVIEW_AUDIT_RECORD_MISSING")
    if not str(policy_version).strip():
        reasons.append("DOCUMENT_REVIEW_POLICY_VERSION_MISSING")
    if not isinstance(lineage_record, dict) or not str(lineage_record.get("lineage_hash", "")).strip():
        reasons.append("DOCUMENT_REVIEW_LINEAGE_RECORD_MISSING")
    return {
        "document_review_status": "BLOCKED" if reasons else "VALID",
        "review_state": str(review_state),
        "reason_codes": sorted(set(reasons)),
        "auto_approved": False,
        "auto_published": False,
        "auto_archived": False,
    }
