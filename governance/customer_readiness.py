from __future__ import annotations

from typing import Any


def evaluate_customer_readiness(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.extend(["MISSING_DOCUMENT_LIBRARY", "MISSING_POLICY_REGISTRY", "MISSING_AUDIT_REGISTRY"])
    else:
        if record.get("document_library_status") != "READY":
            reasons.append("MISSING_DOCUMENT_LIBRARY")
        if record.get("policy_registry_status") != "READY":
            reasons.append("MISSING_POLICY_REGISTRY")
        if record.get("audit_registry_status") != "READY":
            reasons.append("MISSING_AUDIT_REGISTRY")
        if record.get("release_governance_status") != "READY":
            reasons.append("MISSING_RELEASE_GOVERNANCE")
        if record.get("tenant_boundary_status") != "READY":
            reasons.append("MISSING_TENANT_BOUNDARY")
        if not str(record.get("audit_linkage", "")).strip():
            reasons.append("MISSING_AUDIT_LINKAGE")
        if not str(record.get("evidence_linkage", "")).strip():
            reasons.append("MISSING_EVIDENCE_LINKAGE")
    status = "READY_FOR_APPROVAL" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.customer.readiness.v1",
        "customer_readiness_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "connector_write_enabled": False,
        "billing_write_enabled": False,
        "auto_onboarding": False,
        "auto_approval": False,
    }
