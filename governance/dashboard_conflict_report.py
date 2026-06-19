from __future__ import annotations

from typing import Any

from governance.dashboard_validation import validate_dashboard_ownership


DASHBOARD_CONFLICT_REPORT_SCHEMA = "usbay.governance.dashboard_conflict_report.v1"


def dashboard_ownership_report(
    records: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    validation = validate_dashboard_ownership(records=records)
    blocked_capabilities = [
        result
        for result in validation["capability_results"]
        if result.get("status") != "VALID" or result.get("reason_codes")
    ]
    return {
        "schema": DASHBOARD_CONFLICT_REPORT_SCHEMA,
        "dashboard_ownership_status": validation["dashboard_ownership_status"],
        "dashboard_owner_count": validation["dashboard_owner_count"],
        "dashboard_conflict_count": validation["dashboard_conflict_count"],
        "missing_dashboard_owner_count": validation["missing_dashboard_owner_count"],
        "conflicting_dashboard_fields": validation["conflicting_dashboard_fields"],
        "blocked_capabilities": blocked_capabilities,
        "reason_codes": validation["reason_codes"],
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }
