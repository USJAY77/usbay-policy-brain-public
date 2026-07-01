from __future__ import annotations

from typing import Any


def evaluate_document_library_review(record: dict[str, Any] | None, *, human_approval: dict[str, Any] | None = None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_DOCUMENT_LIBRARY")
    if not isinstance(human_approval, dict) or human_approval.get("approved") is not True:
        reasons.append("NO_HUMAN_APPROVAL")
    if isinstance(record, dict):
        if record.get("auto_rewrite") is True:
            reasons.append("AUTO_REWRITE_FORBIDDEN")
        if record.get("auto_publish") is True:
            reasons.append("AUTO_PUBLISH_FORBIDDEN")
        if record.get("auto_delete") is True:
            reasons.append("AUTO_DELETE_FORBIDDEN")
        if record.get("sensitive_data_retention") is True:
            reasons.append("SENSITIVE_DATA_RETENTION_FORBIDDEN")
    status = "APPROVED" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.document_library.review.v1",
        "document_library_review_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "document_rewrite_enabled": False,
        "document_publish_enabled": False,
        "document_delete_enabled": False,
        "auto_approval": False,
        "auto_rewrite": False,
        "auto_publish": False,
        "auto_delete": False,
        "sensitive_data_retention": False,
    }
