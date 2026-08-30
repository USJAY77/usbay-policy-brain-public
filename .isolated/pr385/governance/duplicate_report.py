from __future__ import annotations

from typing import Any

from governance.dashboard_validation import validate_dashboard_ownership
from governance.duplicate_detector import detect_governance_duplicates
from governance.owner_validation import validate_owner_registry
from governance.reason_code_registry import validate_reason_code_registry
from governance.runtime_parity_validator import validate_runtime_parity


DUPLICATE_REPORT_SCHEMA = "usbay.governance.duplicate_report.v1"
DUPLICATE_OWNERSHIP_REPORT_SCHEMA = "usbay.governance.duplicate_ownership_report.v1"
DUPLICATE_REASONCODE_REPORT_SCHEMA = "usbay.governance.duplicate_reasoncode_report.v1"


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


def duplicate_ownership_report() -> dict[str, Any]:
    owners = validate_owner_registry()
    dashboard = validate_dashboard_ownership()
    runtime = validate_runtime_parity()
    duplicates = detect_governance_duplicates()
    blockers: list[str] = []
    if owners["owner_conflict_count"] != 0:
        blockers.append("multiple_aggregate_owners")
    if dashboard["dashboard_conflict_count"] != 0:
        blockers.append("conflicting_dashboard_ownership")
    if runtime["runtime_parity_status"] != "VALID":
        blockers.append("conflicting_runtime_ownership")
    status = "VALID" if not blockers and duplicates["duplicate_status"] == "VALID" else "BLOCKED"
    return {
        "schema": DUPLICATE_OWNERSHIP_REPORT_SCHEMA,
        "duplicate_ownership_status": status,
        "duplicate_owner_count": duplicates["duplicate_owner_count"],
        "duplicate_dashboard_owner_count": duplicates["duplicate_dashboard_owner_count"],
        "duplicate_runtime_owner_count": 0 if "conflicting_runtime_ownership" not in blockers else 1,
        "duplicate_audit_owner_count": duplicates["duplicate_audit_owner_count"],
        "duplicate_evidence_owner_count": duplicates["duplicate_evidence_owner_count"],
        "duplicate_lineage_owner_count": duplicates["duplicate_lineage_owner_count"],
        "blockers": blockers,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }


def duplicate_reasoncode_report() -> dict[str, Any]:
    registry = validate_reason_code_registry()
    duplicates = detect_governance_duplicates()
    duplicate_count = duplicates["duplicate_reason_code_owner_count"]
    return {
        "schema": DUPLICATE_REASONCODE_REPORT_SCHEMA,
        "duplicate_reasoncode_status": "VALID" if registry["status"] == "VALID" and duplicate_count == 0 else "BLOCKED",
        "duplicate_reason_code_owner_count": duplicate_count,
        "duplicate_reason_codes": list(registry["duplicate_reason_codes"]),
        "duplicate_reason_namespaces": list(duplicates["duplicate_reason_namespaces"]),
        "empty_namespaces": list(registry["empty_namespaces"]),
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }
