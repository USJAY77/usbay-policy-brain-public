from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from governance.production_readiness_contracts import parse_timestamp


def _decision(status: str, reasons: list[str] | tuple[str, ...], **extra: Any) -> dict[str, Any]:
    return {
        "schema": "usbay.production.backup.v1",
        "backup_validation_status": status,
        "reason_codes": sorted(set(str(reason) for reason in reasons if reason)),
        "fail_closed": status != "READY",
        "read_only": True,
        "execution_enabled": False,
        "backup_write_enabled": False,
        "auto_backup_created": False,
        "auto_recovered": False,
        "auto_remediated": False,
    } | extra


def validate_backup_readiness(
    backup: dict[str, Any] | None,
    *,
    now: datetime | None = None,
    max_age_hours: float = 24.0,
) -> dict[str, Any]:
    if not isinstance(backup, dict):
        return _decision("BLOCKED", ["BACKUP_RECORD_MALFORMED"])
    reasons: list[str] = []
    if backup.get("backup_exists") is not True:
        reasons.append("BACKUP_MISSING")
    if backup.get("backup_integrity") != "VERIFIED":
        reasons.append("BACKUP_INTEGRITY_NOT_VERIFIED")
    if not str(backup.get("backup_scope", "")).strip():
        reasons.append("BACKUP_SCOPE_MISSING")
    if not str(backup.get("backup_lineage", "")).strip() and not str(backup.get("lineage_hash", "")).strip():
        reasons.append("BACKUP_LINEAGE_MISSING")
    if not str(backup.get("audit_hash", "")).strip():
        reasons.append("BACKUP_AUDIT_MISSING")
    timestamp = parse_timestamp(backup.get("backup_timestamp"))
    if timestamp is None:
        reasons.append("BACKUP_TIMESTAMP_MISSING")
    else:
        effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        age_hours = (effective_now - timestamp).total_seconds() / 3600
        if age_hours < 0 or age_hours > max_age_hours:
            reasons.append("BACKUP_EXPIRED")
    status = "READY" if not reasons else "BLOCKED"
    return _decision(status, reasons, backup_timestamp=str(backup.get("backup_timestamp", "")))
