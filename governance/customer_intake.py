from __future__ import annotations

from typing import Any


def evaluate_customer_intake(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.extend(["MISSING_TENANT_ID", "MISSING_WORKSPACE_ID"])
    else:
        if not str(record.get("tenant_id", "")).strip():
            reasons.append("MISSING_TENANT_ID")
        if not str(record.get("workspace_id", "")).strip():
            reasons.append("MISSING_WORKSPACE_ID")
        if not str(record.get("customer_classification", "")).strip():
            reasons.append("MISSING_CUSTOMER_CLASSIFICATION")
        if not str(record.get("jurisdiction", "")).strip():
            reasons.append("MISSING_JURISDICTION")
        if record.get("governance_terms_accepted") is not True:
            reasons.append("GOVERNANCE_TERMS_NOT_ACCEPTED")
    status = "INTAKE_RECEIVED" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.customer.intake.v1",
        "customer_intake_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "workspace_creation_enabled": False,
        "tenant_creation_enabled": False,
        "auto_onboarding": False,
        "auto_approval": False,
    }
