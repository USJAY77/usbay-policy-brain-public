from __future__ import annotations

from typing import Any

from governance.api_security_contracts import validate_api_security_record


def evaluate_api_inventory(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_api_security_record(record)
    if not validation.valid:
        reasons.extend(code for code in validation.reason_codes if code in {"UNKNOWN_API", "MISSING_API_INVENTORY", "MISSING_CLASSIFICATION"})
    status = "VALID" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.api.inventory.v1",
        "api_inventory_status": status,
        "reason_codes": sorted(set(reasons)),
        "read_only": True,
        "api_invocation_enabled": False,
        "network_access_enabled": False,
    }
