from __future__ import annotations

from typing import Any

from governance.duplicate_detector import detect_governance_duplicates


DUPLICATE_REPORT_SCHEMA = "usbay.governance.duplicate_report.v1"


def duplicate_governance_report() -> dict[str, Any]:
    duplicates = detect_governance_duplicates()
    duplicate_count = (
        duplicates["duplicate_owner_count"]
        + duplicates["duplicate_dashboard_owner_count"]
        + duplicates["duplicate_reason_code_owner_count"]
        + duplicates["duplicate_audit_owner_count"]
        + duplicates["duplicate_evidence_owner_count"]
        + duplicates["duplicate_lineage_owner_count"]
    )
    return {
        "schema": DUPLICATE_REPORT_SCHEMA,
        "duplicate_status": duplicates["duplicate_status"],
        "duplicate_count": duplicate_count,
        "duplicates": duplicates,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }
