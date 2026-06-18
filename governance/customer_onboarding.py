from __future__ import annotations

from typing import Any

from governance.customer_intake import evaluate_customer_intake
from governance.customer_onboarding_contracts import validate_customer_onboarding
from governance.customer_readiness import evaluate_customer_readiness
from governance.customer_verification import evaluate_customer_verification


def evaluate_customer_onboarding(
    *,
    record: dict[str, Any] | None,
    known_tenant_ids: set[str] | None = None,
    assigned_jurisdiction: str | None = None,
    human_approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_customer_onboarding(record)
    if not validation.valid:
        reasons.extend(validation.reason_codes)
    intake = evaluate_customer_intake(record)
    verification = evaluate_customer_verification(
        record,
        known_tenant_ids=known_tenant_ids,
        assigned_jurisdiction=assigned_jurisdiction,
    )
    readiness = evaluate_customer_readiness(record)
    if not isinstance(human_approval, dict) or human_approval.get("approved") is not True:
        reasons.append("NO_HUMAN_APPROVAL")
    for result in (intake, verification, readiness):
        if result.get("fail_closed") is True:
            reasons.extend(result.get("reason_codes", []))
    status = "ACTIVE" if not reasons and validation.status == "ACTIVE" else ("APPROVED" if not reasons else "BLOCKED")
    return {
        "schema": "usbay.customer.onboarding.v1",
        "customer_onboarding_status": status,
        "customer_intake_status": intake["customer_intake_status"],
        "customer_verification_status": verification["customer_verification_status"],
        "customer_readiness_status": readiness["customer_readiness_status"],
        "customer_onboarding_reason_codes": sorted(set(str(reason) for reason in reasons if reason)),
        "pending_customer_count": 0 if status in {"APPROVED", "ACTIVE"} else 1,
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "workspace_creation_enabled": False,
        "tenant_creation_enabled": False,
        "connector_write_enabled": False,
        "billing_write_enabled": False,
        "auto_onboarding": False,
        "auto_approval": False,
        "sensitive_data_logging": False,
    }


def empty_customer_onboarding_dashboard_state() -> dict[str, Any]:
    return {
        "customer_onboarding_status": "BLOCKED",
        "customer_intake_status": "BLOCKED",
        "customer_verification_status": "BLOCKED",
        "customer_readiness_status": "BLOCKED",
        "customer_onboarding_reason_codes": ["MISSING_TENANT_ID", "MISSING_WORKSPACE_ID"],
        "pending_customer_count": 0,
        "fail_closed": True,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "workspace_creation_enabled": False,
        "tenant_creation_enabled": False,
        "connector_write_enabled": False,
        "billing_write_enabled": False,
        "auto_onboarding": False,
        "auto_approval": False,
        "sensitive_data_logging": False,
    }
