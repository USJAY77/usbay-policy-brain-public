from __future__ import annotations

from typing import Any

from governance.capability_manifest import validate_capability_manifest
from governance.dashboard_validation import validate_dashboard_ownership
from governance.duplicate_detector import detect_governance_duplicates
from governance.owner_validation import validate_owner_registry
from governance.provider_deprecation import validate_provider_deprecation
from governance.reason_code_registry import validate_reason_code_registry


RUNTIME_PARITY_VALIDATOR_SCHEMA = "usbay.governance.runtime_parity_validator.v1"
RUNTIME_VALIDATION_REPORT_SCHEMA = "usbay.governance.runtime_validation_report.v1"
REASON_RUNTIME_EVALUATION_MISSING = "RUNTIME_EVALUATION_MISSING"
REASON_RUNTIME_EVALUATION_BLOCKED = "RUNTIME_EVALUATION_BLOCKED"


def validate_runtime_parity(runtime_evaluation: dict[str, Any] | None = None) -> dict[str, Any]:
    dashboard = validate_dashboard_ownership()
    manifest = validate_capability_manifest()
    owners = validate_owner_registry()
    reasons = validate_reason_code_registry()
    duplicates = detect_governance_duplicates()
    providers = validate_provider_deprecation()
    from governance.vision_runtime_parity import validate_vision_runtime_parity

    vision = validate_vision_runtime_parity()
    runtime = runtime_evaluation if isinstance(runtime_evaluation, dict) else {"runtime_evaluation_status": "VALID"}
    runtime_reasons: list[str] = []
    runtime_status = str(runtime.get("runtime_evaluation_status", "BLOCKED"))
    if not runtime:
        runtime_reasons.append(REASON_RUNTIME_EVALUATION_MISSING)
    if runtime_status not in {"VALID", "READY", "VERIFIED"}:
        runtime_reasons.append(REASON_RUNTIME_EVALUATION_BLOCKED)

    checks = {
        "dashboard_state": dashboard["dashboard_ownership_status"],
        "manifest_state": manifest["status"],
        "owner_registry": owners["owner_validation_status"],
        "reason_registry": reasons["status"],
        "provider_registry": providers["provider_status"],
        "duplicate_registry": duplicates["duplicate_status"],
        "vision_runtime_parity": vision["vision_runtime_parity_status"],
        "runtime_evaluation": "VALID" if not runtime_reasons else "BLOCKED",
    }
    blocked = sorted(name for name, status in checks.items() if status not in {"VALID", "READY", "VERIFIED"})
    clean_reasons = sorted(
        set(
            runtime_reasons
            + dashboard["reason_codes"]
            + manifest.get("unknown_controls", [])
            + owners["reason_codes"]
            + reasons.get("duplicate_reason_codes", [])
            + providers["reason_codes"]
            + vision["reason_codes"]
        )
    )
    return {
        "schema": RUNTIME_PARITY_VALIDATOR_SCHEMA,
        "runtime_parity_status": "VALID" if not blocked and not clean_reasons else "BLOCKED",
        "checks": checks,
        "blocked_checks": blocked,
        "reason_codes": clean_reasons,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation_enabled": False,
        "auto_approval_enabled": False,
    }


def runtime_validation_report(runtime_evaluation: dict[str, Any] | None = None) -> dict[str, Any]:
    parity = validate_runtime_parity(runtime_evaluation=runtime_evaluation)
    owners = validate_owner_registry()
    manifest = validate_capability_manifest()
    reasons = validate_reason_code_registry()
    duplicates = detect_governance_duplicates()
    duplicate_ownership_status = (
        "VALID"
        if (
            duplicates["duplicate_owner_count"] == 0
            and duplicates["duplicate_dashboard_owner_count"] == 0
            and parity["runtime_parity_status"] == "VALID"
        )
        else "BLOCKED"
    )
    checks = {
        "runtime_parity": parity["runtime_parity_status"],
        "runtime_ownership": owners["owner_validation_status"],
        "runtime_authority": "VALID" if owners["owner_conflict_count"] == 0 else "BLOCKED",
        "runtime_registry_alignment": manifest["status"],
        "runtime_reason_code_alignment": reasons["status"],
        "runtime_duplicate_ownership": duplicate_ownership_status,
    }
    blockers = sorted(name for name, status in checks.items() if status != "VALID")
    score = round(((len(checks) - len(blockers)) / len(checks)) * 100)
    return {
        "schema": RUNTIME_VALIDATION_REPORT_SCHEMA,
        "runtime_validation_status": "VALID" if not blockers else "BLOCKED",
        "runtime_validation_score": score,
        "checks": checks,
        "blockers": blockers,
        "reason_codes": sorted(set(parity["reason_codes"] + owners["reason_codes"] + reasons["duplicate_reason_codes"])),
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation_enabled": False,
        "auto_approval_enabled": False,
    }
