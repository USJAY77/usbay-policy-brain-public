from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from governance.audit_lineage_validator import validate_audit_lineage
from governance.audit_registry_contracts import AUDIT_REGISTRY_POLICY_VERSION, AUDIT_REGISTRY_SCHEMA, validate_registry_record


def _now_text(now: datetime | None = None) -> str:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return effective_now.isoformat().replace("+00:00", "Z")


def build_audit_registry(records: list[dict[str, Any]] | None, *, now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(records, list):
        records = []
        malformed = True
    else:
        malformed = False
    validation_reasons: list[str] = ["AUDIT_REGISTRY_RECORDS_MALFORMED"] if malformed else []
    tamper_reasons: list[str] = []
    for record in records:
        validation = validate_registry_record(record)
        if validation.status == "TAMPER_DETECTED":
            tamper_reasons.extend(validation.reason_codes)
        elif not validation.valid:
            validation_reasons.extend(validation.reason_codes)
    lineage = validate_audit_lineage(records)
    reason_codes = sorted(set(validation_reasons + list(lineage.get("reason_codes", []))))
    tamper_status = "TAMPER_DETECTED" if tamper_reasons or lineage.get("tamper_status") == "TAMPER_DETECTED" else "NO_TAMPER_DETECTED"
    status = "TAMPER_DETECTED" if tamper_status == "TAMPER_DETECTED" else ("BLOCKED" if reason_codes else "VERIFIED")
    return {
        "schema": AUDIT_REGISTRY_SCHEMA,
        "audit_registry_status": status,
        "audit_registry_record_count": len(records),
        "audit_registry_tamper_status": tamper_status,
        "audit_registry_last_verified": _now_text(now),
        "audit_registry_reason_codes": reason_codes,
        "governance_history_status": "AVAILABLE_READ_ONLY" if records and status == "VERIFIED" else "BLOCKED",
        "policy_version": AUDIT_REGISTRY_POLICY_VERSION,
        "records": list(records),
        "lineage_validation": lineage,
        "fail_closed": status != "VERIFIED",
        "read_only": True,
        "mutation_enabled": False,
        "delete_enabled": False,
        "repair_enabled": False,
        "auto_repaired": False,
        "auto_fixed": False,
        "auto_trusted": False,
        "auto_verified": False,
        "auto_merged": False,
        "auto_deployed": False,
    }


def empty_audit_registry_dashboard_state() -> dict[str, Any]:
    return build_audit_registry([])
