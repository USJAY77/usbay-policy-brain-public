from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from governance.production_readiness_contracts import parse_timestamp


def _decision(status: str, reasons: list[str] | tuple[str, ...], **extra: Any) -> dict[str, Any]:
    return {
        "schema": "usbay.production.recovery.v1",
        "recovery_validation_status": status,
        "reason_codes": sorted(set(str(reason) for reason in reasons if reason)),
        "fail_closed": status != "READY",
        "read_only": True,
        "execution_enabled": False,
        "rollback_enabled": False,
        "auto_recover": False,
        "auto_rollback": False,
        "auto_remediate": False,
    } | extra


def validate_recovery_readiness(
    recovery: dict[str, Any] | None,
    *,
    now: datetime | None = None,
    max_age_hours: float = 168.0,
) -> dict[str, Any]:
    if not isinstance(recovery, dict):
        return _decision("BLOCKED", ["RECOVERY_RECORD_MALFORMED"])
    reasons: list[str] = []
    if not str(recovery.get("recovery_plan", "")).strip():
        reasons.append("RECOVERY_PLAN_MISSING")
    if not str(recovery.get("recovery_owner", "")).strip():
        reasons.append("RECOVERY_OWNER_MISSING")
    if recovery.get("recovery_test") != "PASSED":
        reasons.append("RECOVERY_TEST_NOT_PASSED")
    if not str(recovery.get("recovery_evidence", "")).strip():
        reasons.append("RECOVERY_EVIDENCE_MISSING")
    if not str(recovery.get("audit_hash", "")).strip():
        reasons.append("RECOVERY_AUDIT_MISSING")
    if not str(recovery.get("lineage_hash", "")).strip():
        reasons.append("RECOVERY_LINEAGE_MISSING")
    timestamp = parse_timestamp(recovery.get("recovery_timestamp"))
    if timestamp is None:
        reasons.append("RECOVERY_TIMESTAMP_MISSING")
    else:
        effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        age_hours = (effective_now - timestamp).total_seconds() / 3600
        if age_hours < 0 or age_hours > max_age_hours:
            reasons.append("RECOVERY_TEST_EXPIRED")
    status = "READY" if not reasons else "BLOCKED"
    return _decision(status, reasons, recovery_timestamp=str(recovery.get("recovery_timestamp", "")))
