from __future__ import annotations

from datetime import datetime
from typing import Any

from governance.license_contracts import SUPPORTED_LICENSE_TIERS, parse_timestamp, validate_license_record


def evaluate_license_lifecycle(record: dict[str, Any] | None, *, now: datetime | None = None) -> dict[str, Any]:
    validation = validate_license_record(record, now=now)
    reasons = list(validation.reason_codes)
    tier = str(record.get("license_tier", "UNKNOWN")) if isinstance(record, dict) else "UNKNOWN"
    state = str(record.get("license_state", "BLOCKED")) if isinstance(record, dict) else "BLOCKED"
    expires_at = parse_timestamp(record.get("expires_at")) if isinstance(record, dict) else None
    expiry_status = "ACTIVE" if validation.valid and expires_at is not None else "BLOCKED"
    if "EXPIRED_LICENSE" in reasons:
        expiry_status = "EXPIRED"
    if tier not in SUPPORTED_LICENSE_TIERS:
        tier = "UNKNOWN"
    status = state if validation.valid else "BLOCKED"
    return {
        "schema": "usbay.license.lifecycle.v1",
        "license_status": status,
        "license_tier": tier,
        "license_expiry_status": expiry_status,
        "reason_codes": sorted(set(str(reason) for reason in reasons if reason)),
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "billing_execution_enabled": False,
        "payment_processing_enabled": False,
        "auto_renewal": False,
        "auto_upgrade": False,
        "auto_assignment": False,
    }
