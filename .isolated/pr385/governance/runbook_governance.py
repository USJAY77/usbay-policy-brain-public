from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from governance.production_readiness_contracts import parse_timestamp


def _decision(status: str, reasons: list[str] | tuple[str, ...], **extra: Any) -> dict[str, Any]:
    return {
        "schema": "usbay.production.runbook.v1",
        "runbook_status": status,
        "reason_codes": sorted(set(str(reason) for reason in reasons if reason)),
        "fail_closed": status != "READY",
        "read_only": True,
        "execution_enabled": False,
        "deploy_enabled": False,
        "auto_runbook_approved": False,
        "auto_deploy": False,
        "auto_remediate": False,
    } | extra


def validate_runbook_governance(
    runbook: dict[str, Any] | None,
    *,
    now: datetime | None = None,
    max_review_age_hours: float = 720.0,
) -> dict[str, Any]:
    if not isinstance(runbook, dict):
        return _decision("BLOCKED", ["RUNBOOK_RECORD_MALFORMED"])
    reasons: list[str] = []
    if runbook.get("runbook_exists") is not True:
        reasons.append("RUNBOOK_MISSING")
    if not str(runbook.get("runbook_owner", "")).strip():
        reasons.append("RUNBOOK_OWNER_MISSING")
    if not str(runbook.get("runbook_version", "")).strip():
        reasons.append("RUNBOOK_VERSION_MISSING")
    if runbook.get("runbook_review") != "APPROVED":
        reasons.append("RUNBOOK_REVIEW_NOT_APPROVED")
    if not str(runbook.get("audit_hash", "")).strip():
        reasons.append("RUNBOOK_AUDIT_MISSING")
    if not str(runbook.get("lineage_hash", "")).strip():
        reasons.append("RUNBOOK_LINEAGE_MISSING")
    timestamp = parse_timestamp(runbook.get("review_timestamp"))
    if timestamp is None:
        reasons.append("RUNBOOK_REVIEW_TIMESTAMP_MISSING")
    else:
        effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        age_hours = (effective_now - timestamp).total_seconds() / 3600
        if age_hours < 0 or age_hours > max_review_age_hours:
            reasons.append("RUNBOOK_REVIEW_EXPIRED")
    status = "READY" if not reasons else "BLOCKED"
    return _decision(status, reasons, review_timestamp=str(runbook.get("review_timestamp", "")))
