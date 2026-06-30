from __future__ import annotations

from typing import Any

from governance.tenant_boundary_contracts import TENANT_BOUNDARY_DECISION_SCHEMA, validate_tenant_identity
from governance.tenant_namespace_registry import build_namespace_registry, resolve_namespace


def _decision(status: str, reasons: tuple[str, ...] | list[str], **extra: Any) -> dict[str, Any]:
    return {
        "schema": TENANT_BOUNDARY_DECISION_SCHEMA,
        "decision": status,
        "reason_codes": sorted(set(str(code) for code in reasons if code)),
        "fail_closed": status != "ALLOWED_WITHIN_TENANT",
        "copy_enabled": False,
        "move_enabled": False,
        "sync_enabled": False,
        "export_enabled": False,
        "delete_enabled": False,
        "share_enabled": False,
        "publish_enabled": False,
        "deploy_enabled": False,
        "merge_enabled": False,
        "push_enabled": False,
        "rollback_enabled": False,
        "auto_tenant_provisioned": False,
        "auto_tenant_migrated": False,
        "auto_tenant_shared": False,
        "auto_tenant_merged": False,
    } | extra


def evaluate_tenant_identity(tenant: dict[str, Any] | None) -> dict[str, Any]:
    validation = validate_tenant_identity(tenant)
    return _decision("BLOCKED" if not validation.valid else "REVIEW_REQUIRED", validation.reason_codes)


def _evaluate_namespace(tenant: dict[str, Any] | None, namespace_field: str, namespace: str | None = None) -> dict[str, Any]:
    validation = validate_tenant_identity(tenant)
    if not validation.valid:
        return _decision("BLOCKED", validation.reason_codes)
    registry = build_namespace_registry([tenant])
    requested_namespace = namespace if namespace is not None else str(tenant.get(namespace_field, ""))
    status, reasons = resolve_namespace(registry, tenant_id=str(tenant.get("tenant_id", "")), namespace=requested_namespace)
    return _decision(status, reasons)


def evaluate_policy_boundary(tenant: dict[str, Any] | None, namespace: str | None = None) -> dict[str, Any]:
    return _evaluate_namespace(tenant, "policy_namespace", namespace)


def evaluate_evidence_boundary(tenant: dict[str, Any] | None, namespace: str | None = None) -> dict[str, Any]:
    return _evaluate_namespace(tenant, "evidence_namespace", namespace)


def evaluate_audit_boundary(tenant: dict[str, Any] | None, namespace: str | None = None) -> dict[str, Any]:
    return _evaluate_namespace(tenant, "audit_namespace", namespace)


def evaluate_release_boundary(tenant: dict[str, Any] | None, namespace: str | None = None) -> dict[str, Any]:
    return _evaluate_namespace(tenant, "release_namespace", namespace)


def evaluate_document_boundary(tenant: dict[str, Any] | None, namespace: str | None = None) -> dict[str, Any]:
    return _evaluate_namespace(tenant, "document_namespace", namespace)


def evaluate_cross_tenant_request(
    *,
    source_tenant_id: str,
    target_tenant_id: str,
    namespace: str,
    human_approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not source_tenant_id or not target_tenant_id:
        reasons.append("TENANT_ID_MISSING")
    if source_tenant_id != target_tenant_id:
        reasons.append("TENANT_CROSS_TENANT_ACCESS_BLOCKED")
    if namespace in {"*", "global", "GLOBAL", "default", "DEFAULT"}:
        reasons.append("TENANT_IMPLICIT_OR_WILDCARD_BLOCKED")
    if not isinstance(human_approval, dict) or human_approval.get("approved") is not True:
        reasons.append("TENANT_BOUNDARY_CHANGE_APPROVAL_MISSING")
    status = "ALLOWED_WITHIN_TENANT" if not reasons else "BLOCKED"
    return _decision(status, reasons, cross_tenant_access_status="BLOCKED" if reasons else "ALLOWED_WITHIN_TENANT")


def empty_tenant_boundary_dashboard_state() -> dict[str, Any]:
    return {
        "tenant_boundary_status": "BLOCKED",
        "tenant_id": "",
        "tenant_classification": "",
        "tenant_region": "",
        "tenant_policy_namespace": "",
        "tenant_evidence_namespace": "",
        "tenant_audit_namespace": "",
        "tenant_release_namespace": "",
        "tenant_document_namespace": "",
        "cross_tenant_access_status": "BLOCKED",
        "tenant_boundary_reason_codes": ["TENANT_ID_MISSING"],
        "auto_tenant_provisioned": False,
        "auto_tenant_migrated": False,
        "auto_tenant_shared": False,
        "auto_tenant_merged": False,
        "global_tenant_access": False,
    }
