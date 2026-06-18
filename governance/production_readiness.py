from __future__ import annotations

from typing import Any

from governance.production_readiness_contracts import validate_production_readiness


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
