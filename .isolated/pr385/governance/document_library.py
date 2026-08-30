from __future__ import annotations

from typing import Any

from governance.document_library_contracts import validate_document_library
from governance.document_library_index import evaluate_document_library_index
from governance.document_library_registry import DocumentLibraryRegistry
from governance.document_library_review import evaluate_document_library_review


def evaluate_document_library(
    *,
    record: dict[str, Any] | None,
    registry: DocumentLibraryRegistry | None = None,
    requesting_tenant_id: str = "",
    human_approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_document_library(record)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("UNKNOWN_DOCUMENT_LIBRARY",))
    if isinstance(record, dict):
        if str(record.get("tenant_id", "")) != str(requesting_tenant_id):
            reasons.append("CROSS_TENANT_LIBRARY_ACCESS")
    registry_records = registry.list_libraries() if isinstance(registry, DocumentLibraryRegistry) else ([record] if isinstance(record, dict) else [])
    registry_summary = DocumentLibraryRegistry(registry_records).summary()
    index = evaluate_document_library_index(record)
    review = evaluate_document_library_review(record, human_approval=human_approval)
    if registry_summary["document_library_registry_status"] != "VALID":
        reasons.extend(registry_summary["document_library_reason_codes"])
    if index["document_library_index_status"] != "INDEXED":
        reasons.extend(index["reason_codes"])
    if review["document_library_review_status"] != "APPROVED":
        reasons.extend(review["reason_codes"])
    status = "ACTIVE" if not reasons and validation.status == "ACTIVE" else ("APPROVED" if not reasons else "BLOCKED")
    return {
        "schema": "usbay.document_library.record.v1",
        "document_library_status": status,
        "document_library_count": registry_summary["document_library_count"],
        "document_library_workspace_status": "VALID"
        if "MISSING_WORKSPACE" not in reasons and "CROSS_TENANT_LIBRARY_ACCESS" not in reasons
        else "BLOCKED",
        "document_library_index_status": index["document_library_index_status"],
        "document_library_review_status": review["document_library_review_status"],
        "document_library_reason_codes": sorted(set(str(reason) for reason in reasons if reason)),
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "browser_control_enabled": False,
        "shell_control_enabled": False,
        "connector_write_enabled": False,
        "document_rewrite_enabled": False,
        "document_publish_enabled": False,
        "document_delete_enabled": False,
        "auto_classification": False,
        "auto_approval": False,
        "raw_payload_logging": False,
        "sensitive_data_retention": False,
    }


def empty_document_library_dashboard_state() -> dict[str, Any]:
    return {
        "document_library_status": "BLOCKED",
        "document_library_count": 0,
        "document_library_workspace_status": "BLOCKED",
        "document_library_index_status": "BLOCKED",
        "document_library_review_status": "BLOCKED",
        "document_library_reason_codes": ["UNKNOWN_DOCUMENT_LIBRARY"],
        "fail_closed": True,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "browser_control_enabled": False,
        "shell_control_enabled": False,
        "connector_write_enabled": False,
        "document_rewrite_enabled": False,
        "document_publish_enabled": False,
        "document_delete_enabled": False,
        "auto_classification": False,
        "auto_approval": False,
        "raw_payload_logging": False,
        "sensitive_data_retention": False,
    }
