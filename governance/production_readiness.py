from __future__ import annotations

from typing import Any

from governance.audit_normalization import audit_normalization_report
from governance.capability_manifest import CAPABILITY_MANIFEST, validate_capability_manifest
from governance.duplicate_detector import detect_governance_duplicates
from governance.evidence_normalization import evidence_normalization_report
from governance.lineage_normalization import lineage_normalization_report
from governance.owner_validation import validate_owner_registry
from governance.production_readiness_contracts import validate_production_readiness
from governance.provider_deprecation import validate_provider_deprecation
from governance.reason_code_registry import validate_reason_code_registry
from governance.runtime_parity_validator import validate_runtime_parity


def _is_ready(result: dict[str, Any] | None, status_key: str) -> bool:
    return isinstance(result, dict) and result.get(status_key) == "READY" and result.get("fail_closed") is False


def evaluate_production_readiness(
    *,
    readiness_record: dict[str, Any] | None,
    backup_validation: dict[str, Any] | None,
    recovery_validation: dict[str, Any] | None,
    runbook_governance: dict[str, Any] | None,
    release_readiness: dict[str, Any] | None,
    environment_status: str,
    tenant_boundary_status: str,
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_production_readiness(readiness_record)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("PRODUCTION_READINESS_CONTRACT_INVALID",))
    if not _is_ready(backup_validation, "backup_validation_status"):
        reasons.extend((backup_validation or {}).get("reason_codes", []) if isinstance(backup_validation, dict) else [])
        reasons.append("PRODUCTION_BACKUP_NOT_READY")
    if not _is_ready(recovery_validation, "recovery_validation_status"):
        reasons.extend((recovery_validation or {}).get("reason_codes", []) if isinstance(recovery_validation, dict) else [])
        reasons.append("PRODUCTION_RECOVERY_NOT_READY")
    if not _is_ready(runbook_governance, "runbook_status"):
        reasons.extend((runbook_governance or {}).get("reason_codes", []) if isinstance(runbook_governance, dict) else [])
        reasons.append("PRODUCTION_RUNBOOK_NOT_READY")
    if not _is_ready(release_readiness, "release_readiness_status"):
        reasons.extend((release_readiness or {}).get("reason_codes", []) if isinstance(release_readiness, dict) else [])
        reasons.append("PRODUCTION_RELEASE_NOT_READY")
    if str(environment_status) != "READY":
        reasons.append("PRODUCTION_ENVIRONMENT_NOT_READY")
    if str(tenant_boundary_status) != "READY":
        reasons.append("PRODUCTION_TENANT_BOUNDARY_NOT_READY")
    status = "READY" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.production.environment.v1",
        "production_readiness_status": status,
        "backup_validation_status": (backup_validation or {}).get("backup_validation_status", "BLOCKED")
        if isinstance(backup_validation, dict)
        else "BLOCKED",
        "recovery_validation_status": (recovery_validation or {}).get("recovery_validation_status", "BLOCKED")
        if isinstance(recovery_validation, dict)
        else "BLOCKED",
        "runbook_status": (runbook_governance or {}).get("runbook_status", "BLOCKED")
        if isinstance(runbook_governance, dict)
        else "BLOCKED",
        "release_readiness_status": (release_readiness or {}).get("release_readiness_status", "BLOCKED")
        if isinstance(release_readiness, dict)
        else "BLOCKED",
        "production_reason_codes": sorted(set(str(reason) for reason in reasons if reason)),
        "fail_closed": status != "READY",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "rollback_execution_enabled": False,
        "connector_write_enabled": False,
        "browser_control_enabled": False,
        "shell_control_enabled": False,
        "auto_deploy": False,
        "auto_release": False,
        "auto_rollback": False,
        "auto_recover": False,
        "auto_remediate": False,
    }


def empty_production_readiness_dashboard_state() -> dict[str, Any]:
    return {
        "production_readiness_status": "BLOCKED",
        "backup_validation_status": "BLOCKED",
        "recovery_validation_status": "BLOCKED",
        "runbook_status": "BLOCKED",
        "release_readiness_status": "BLOCKED",
        "production_reason_codes": ["PRODUCTION_READINESS_NOT_EVALUATED"],
        "fail_closed": True,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "rollback_execution_enabled": False,
        "connector_write_enabled": False,
        "browser_control_enabled": False,
        "shell_control_enabled": False,
        "auto_deploy": False,
        "auto_release": False,
        "auto_rollback": False,
        "auto_recover": False,
        "auto_remediate": False,
    }


def consolidation_production_readiness_report(runtime_evaluation: dict[str, Any] | None = None) -> dict[str, Any]:
    ownership = validate_owner_registry()
    duplicates = detect_governance_duplicates()
    audit = audit_normalization_report()
    evidence = evidence_normalization_report()
    lineage = lineage_normalization_report()
    manifest = validate_capability_manifest()
    reasons = validate_reason_code_registry()
    providers = validate_provider_deprecation()
    runtime = validate_runtime_parity(runtime_evaluation=runtime_evaluation)

    checks = {
        "ownership_consistency": ownership["owner_validation_status"],
        "dashboard_consistency": "VALID" if duplicates["duplicate_dashboard_owner_count"] == 0 else "BLOCKED",
        "audit_consistency": audit["audit_status"],
        "evidence_consistency": evidence["evidence_status"],
        "reason_code_consistency": reasons["status"],
        "manifest_consistency": manifest["status"],
        "provider_consistency": providers["provider_status"],
        "runtime_parity": runtime["runtime_parity_status"],
    }
    blockers = sorted(name for name, status in checks.items() if status not in {"VALID", "READY", "VERIFIED"})
    score = round(((len(checks) - len(blockers)) / len(checks)) * 100)
    normalized = _normalized_capability_rows(audit, evidence, lineage)
    remaining_risks = [] if not blockers else ["Production readiness is blocked until all consistency checks are VALID."]
    return {
        "schema": "usbay.governance.consolidation_production_readiness.v1",
        "production_readiness_status": "READY" if not blockers else "BLOCKED",
        "production_readiness_score": score,
        "production_blockers": blockers,
        "remaining_risks": remaining_risks,
        "checks": checks,
        "ownership_consistency": checks["ownership_consistency"],
        "dashboard_consistency": checks["dashboard_consistency"],
        "audit_consistency": checks["audit_consistency"],
        "evidence_consistency": checks["evidence_consistency"],
        "reason_code_consistency": checks["reason_code_consistency"],
        "manifest_consistency": checks["manifest_consistency"],
        "normalized_capabilities": normalized,
        "duplicate_owner_count": duplicates["duplicate_owner_count"],
        "duplicate_dashboard_owner_count": duplicates["duplicate_dashboard_owner_count"],
        "duplicate_reason_code_owner_count": duplicates["duplicate_reason_code_owner_count"],
        "deprecated_provider_count": providers["deprecated_provider_count"],
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation_enabled": False,
        "auto_approval_enabled": False,
    }


def _normalized_capability_rows(
    audit: dict[str, Any],
    evidence: dict[str, Any],
    lineage: dict[str, Any],
) -> list[dict[str, Any]]:
    audit_by_id = {row["capability_id"]: row for row in audit["capabilities"]}
    evidence_by_id = {row["capability_id"]: row for row in evidence["capabilities"]}
    lineage_by_id = {row["capability_id"]: row for row in lineage["capabilities"]}
    rows: list[dict[str, Any]] = []
    for capability in CAPABILITY_MANIFEST:
        capability_id = str(capability["capability_id"])
        controls = tuple(str(control) for control in capability.get("controls", ()))
        rows.append(
            {
                "capability_id": capability_id,
                "audit_status": audit_by_id.get(capability_id, {}).get("audit_status", "BLOCKED"),
                "evidence_status": evidence_by_id.get(capability_id, {}).get("evidence_status", "BLOCKED"),
                "lineage_status": lineage_by_id.get(capability_id, {}).get("lineage_status", "BLOCKED"),
                "human_approval_status": "REQUIRED" if "human_approval" in controls else "NOT_REQUIRED",
            }
        )
    return rows
