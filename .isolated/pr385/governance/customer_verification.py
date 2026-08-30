from __future__ import annotations

from typing import Any


def evaluate_customer_verification(
    record: dict[str, Any] | None,
    *,
    known_tenant_ids: set[str] | None = None,
    assigned_jurisdiction: str | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("MISSING_TENANT_ID")
    else:
        tenant_id = str(record.get("tenant_id", ""))
        if not tenant_id:
            reasons.append("MISSING_TENANT_ID")
        elif known_tenant_ids and tenant_id in known_tenant_ids:
            reasons.append("DUPLICATE_TENANT_IDENTITY")
        jurisdiction = str(record.get("jurisdiction", ""))
        if not jurisdiction:
            reasons.append("MISSING_JURISDICTION")
        elif assigned_jurisdiction and jurisdiction != str(assigned_jurisdiction):
            reasons.append("CONFLICTING_JURISDICTION")
        if not str(record.get("risk_classification", "")).strip():
            reasons.append("MISSING_RISK_CLASSIFICATION")
        if not str(record.get("workspace_owner", "")).strip():
            reasons.append("MISSING_WORKSPACE_OWNER")
    status = "VERIFIED" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.customer.verification.v1",
        "customer_verification_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "tenant_creation_enabled": False,
        "billing_write_enabled": False,
        "auto_approval": False,
    }
