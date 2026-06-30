from __future__ import annotations

from typing import Any

from governance.duplicate_detector import detect_governance_duplicates
from governance.vision_consolidation import validate_vision_consolidation
from governance.vision_dashboard_validation import validate_vision_dashboard
from governance.vision_runtime_parity import validate_vision_runtime_parity


VISION_READINESS_SCHEMA = "usbay.governance.vision_readiness.v1"


def vision_readiness_report(runtime_truth: dict[str, Any] | None = None) -> dict[str, Any]:
    consolidation = validate_vision_consolidation()
    dashboard = validate_vision_dashboard()
    runtime = validate_vision_runtime_parity(runtime_truth=runtime_truth)
    duplicates = detect_governance_duplicates()
    checks = {
        "vision_consolidation": consolidation["vision_consolidation_status"],
        "vision_dashboard": dashboard["vision_dashboard_status"],
        "vision_runtime_parity": runtime["vision_runtime_parity_status"],
        "duplicate_owners": "VALID" if duplicates["duplicate_owner_count"] == 0 else "BLOCKED",
        "duplicate_dashboard_owners": "VALID" if duplicates["duplicate_dashboard_owner_count"] == 0 else "BLOCKED",
        "duplicate_reason_code_owners": "VALID" if duplicates["duplicate_reason_code_owner_count"] == 0 else "BLOCKED",
    }
    blockers = sorted(name for name, status in checks.items() if status != "VALID")
    score = round(((len(checks) - len(blockers)) / len(checks)) * 100)
    return {
        "schema": VISION_READINESS_SCHEMA,
        "vision_readiness_status": "READY" if not blockers else "BLOCKED",
        "vision_readiness_score": score,
        "vision_blockers": blockers,
        "vision_drift_count": len(blockers),
        "duplicate_owners": duplicates["duplicate_owner_count"],
        "duplicate_dashboard_owners": duplicates["duplicate_dashboard_owner_count"],
        "duplicate_reason_code_owners": duplicates["duplicate_reason_code_owner_count"],
        "runtime_parity_status": runtime["vision_runtime_parity_status"],
        "checks": checks,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation_enabled": False,
        "auto_approval_enabled": False,
    }
