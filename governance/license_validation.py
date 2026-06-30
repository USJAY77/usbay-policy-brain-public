from __future__ import annotations

from datetime import datetime
from typing import Any

from governance.license_contracts import validate_license_record
from governance.license_entitlements import evaluate_license_entitlements
from governance.license_lifecycle import evaluate_license_lifecycle
from governance.license_registry import LicenseRegistry


def evaluate_license_governance(
    *,
    record: dict[str, Any] | None,
    entitlement_context: dict[str, Any] | None = None,
    registry: LicenseRegistry | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_license_record(record, now=now)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("MISSING_LICENSE",))
    lifecycle = evaluate_license_lifecycle(record, now=now)
    entitlements = evaluate_license_entitlements(record, entitlement_context, now=now)
    registry_records = registry.list_licenses() if isinstance(registry, LicenseRegistry) else ([record] if isinstance(record, dict) else [])
    registry_summary = LicenseRegistry(registry_records, now=now).summary()
    for result in (lifecycle, entitlements, registry_summary):
        reasons.extend(result.get("reason_codes", []))
        reasons.extend(result.get("license_reason_codes", []))
    reason_codes = sorted(set(str(reason) for reason in reasons if reason))
    status = "ACTIVE" if not reason_codes and validation.status == "ACTIVE" else "BLOCKED"
    return {
        "schema": "usbay.license.validation.v1",
        "license_status": status,
        "license_tier": lifecycle["license_tier"],
        "license_expiry_status": lifecycle["license_expiry_status"] if status == "ACTIVE" else lifecycle["license_expiry_status"],
        "license_entitlement_status": entitlements["license_entitlement_status"],
        "license_reason_codes": reason_codes,
        "active_license_count": registry_summary["active_license_count"],
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "billing_execution_enabled": False,
        "payment_processing_enabled": False,
        "deployment_enabled": False,
        "connector_write_enabled": False,
        "auto_renewal": False,
        "auto_upgrade": False,
        "auto_assignment": False,
        "sensitive_data_logging": False,
    }


def empty_license_dashboard_state() -> dict[str, Any]:
    return {
        "license_status": "BLOCKED",
        "license_tier": "UNKNOWN",
        "license_expiry_status": "BLOCKED",
        "license_entitlement_status": "BLOCKED",
        "license_reason_codes": ["MISSING_LICENSE"],
        "active_license_count": 0,
        "fail_closed": True,
        "read_only": True,
        "billing_execution_enabled": False,
        "payment_processing_enabled": False,
        "deployment_enabled": False,
        "connector_write_enabled": False,
        "auto_renewal": False,
        "auto_upgrade": False,
        "auto_assignment": False,
        "sensitive_data_logging": False,
    }
