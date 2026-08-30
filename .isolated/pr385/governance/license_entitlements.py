from __future__ import annotations

from datetime import datetime
from typing import Any

from governance.license_contracts import validate_license_record


DEPENDENCY_FIELDS = {
    "approved_onboarding": "ENTITLEMENT_MISMATCH",
    "active_policy_registry": "GOVERNANCE_MODULE_NOT_LICENSED",
    "active_audit_registry": "AUDIT_EXPORT_NOT_LICENSED",
    "active_document_library": "GOVERNANCE_MODULE_NOT_LICENSED",
    "active_tenant_boundary": "GOVERNANCE_MODULE_NOT_LICENSED",
}


def evaluate_license_entitlements(
    license_record: dict[str, Any] | None,
    context: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_license_record(license_record, now=now)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("MISSING_LICENSE",))
    if not isinstance(license_record, dict):
        return _entitlement_result(reasons or ["MISSING_LICENSE"])

    entitlement_context = context if isinstance(context, dict) else {}
    entitlements = set(str(item) for item in license_record.get("entitlements", []) if item)
    requested_capability = str(entitlement_context.get("requested_capability", ""))
    if str(entitlement_context.get("customer_id", license_record.get("customer_id", ""))) != str(license_record.get("customer_id", "")):
        reasons.append("ENTITLEMENT_MISMATCH")
    if str(entitlement_context.get("tenant_id", license_record.get("tenant_id", ""))) != str(license_record.get("tenant_id", "")):
        reasons.append("TENANT_MISMATCH")
    if str(entitlement_context.get("workspace_id", license_record.get("workspace_id", ""))) != str(
        license_record.get("workspace_id", "")
    ):
        reasons.append("WORKSPACE_MISMATCH")
    for field, reason in DEPENDENCY_FIELDS.items():
        if entitlement_context.get(field, True) is not True:
            reasons.append(reason)
    if requested_capability and requested_capability not in entitlements:
        if requested_capability == "AUDIT_EXPORT":
            reasons.append("AUDIT_EXPORT_NOT_LICENSED")
        elif requested_capability.startswith("GOVERNANCE_MODULE"):
            reasons.append("GOVERNANCE_MODULE_NOT_LICENSED")
        else:
            reasons.append("CAPABILITY_NOT_LICENSED")
    if requested_capability == "SOVEREIGN_DEPLOYMENT" and license_record.get("license_tier") != "SOVEREIGN":
        reasons.append("SOVEREIGN_LICENSE_REQUIRED")
    if entitlement_context.get("sovereign_deployment_entitlement", True) is not True:
        reasons.append("SOVEREIGN_LICENSE_REQUIRED")
    return _entitlement_result(reasons)


def _entitlement_result(reasons: list[str]) -> dict[str, Any]:
    clean_reasons = sorted(set(str(reason) for reason in reasons if reason))
    return {
        "schema": "usbay.license.entitlement.v1",
        "license_entitlement_status": "VALID" if not clean_reasons else "BLOCKED",
        "reason_codes": clean_reasons,
        "fail_closed": bool(clean_reasons),
        "read_only": True,
        "billing_execution_enabled": False,
        "payment_processing_enabled": False,
        "deployment_enabled": False,
        "connector_write_enabled": False,
        "auto_renewal": False,
        "auto_upgrade": False,
        "auto_assignment": False,
    }
