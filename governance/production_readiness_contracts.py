from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


PRODUCTION_READINESS_SCHEMA = "usbay.production.readiness.v1"
PRODUCTION_BACKUP_SCHEMA = "usbay.production.backup.v1"
PRODUCTION_RECOVERY_SCHEMA = "usbay.production.recovery.v1"
PRODUCTION_ENVIRONMENT_SCHEMA = "usbay.production.environment.v1"
PRODUCTION_RUNBOOK_SCHEMA = "usbay.production.runbook.v1"
PRODUCTION_RELEASE_READINESS_SCHEMA = "usbay.production.release_readiness.v1"
PRODUCTION_READINESS_POLICY_VERSION = "usbay.pb-production-readiness.governed-production-readiness.v1"

ALLOWED_READINESS_STATUSES = frozenset({"READY", "REVIEW_REQUIRED", "BLOCKED"})
REQUIRED_READINESS_FIELDS = (
    "readiness_id",
    "environment_id",
    "tenant_id",
    "policy_version",
    "policy_hash",
    "audit_hash",
    "evidence_hash",
    "lineage_hash",
    "backup_status",
    "recovery_status",
    "runbook_status",
    "release_status",
    "readiness_status",
    "reason_codes",
    "created_at",
    "fail_closed",
)
SENSITIVE_MARKERS = (
    "password",
    "secret",
    "token",
    "cookie",
    "authorization",
    "api_key",
    "private_key",
    "raw_payload",
    "raw_screenshot",
)


@dataclass(frozen=True)
class ProductionReadinessValidation:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reason_codes": list(self.reason_codes)}


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def contains_sensitive_marker(value: Any) -> bool:
    if isinstance(value, dict):
        text = " ".join(str(item).lower() for pair in value.items() for item in pair)
    elif isinstance(value, list):
        text = " ".join(str(item).lower() for item in value)
    else:
        text = str(value).lower()
    return any(marker in text for marker in SENSITIVE_MARKERS)


def canonical_production_readiness_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "readiness_id": str(record.get("readiness_id", "")),
        "environment_id": str(record.get("environment_id", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "policy_version": str(record.get("policy_version", "")),
        "policy_hash": str(record.get("policy_hash", "")),
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "backup_status": str(record.get("backup_status", "")),
        "recovery_status": str(record.get("recovery_status", "")),
        "runbook_status": str(record.get("runbook_status", "")),
        "release_status": str(record.get("release_status", "")),
        "readiness_status": str(record.get("readiness_status", "")),
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "created_at": str(record.get("created_at", "")),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_readiness_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_production_readiness_payload(record))


def _missing_hash(value: Any) -> bool:
    return not isinstance(value, str) or not value.strip()


def validate_production_readiness(record: dict[str, Any] | None) -> ProductionReadinessValidation:
    if not isinstance(record, dict):
        return ProductionReadinessValidation(False, "BLOCKED", ("PRODUCTION_READINESS_MALFORMED",))
    reasons: list[str] = []
    if record.get("schema") != PRODUCTION_READINESS_SCHEMA:
        reasons.append("PRODUCTION_READINESS_SCHEMA_INVALID")
    for field in REQUIRED_READINESS_FIELDS:
        if record.get(field) in ("", None):
            reasons.append(f"PRODUCTION_{field.upper()}_MISSING")
    for hash_field in ("policy_hash", "audit_hash", "evidence_hash", "lineage_hash"):
        if _missing_hash(record.get(hash_field)):
            reasons.append(f"PRODUCTION_{hash_field.upper()}_MISSING")
    for status_field in ("backup_status", "recovery_status", "runbook_status", "release_status", "readiness_status"):
        status = str(record.get(status_field, ""))
        if status not in ALLOWED_READINESS_STATUSES:
            reasons.append(f"PRODUCTION_{status_field.upper()}_UNKNOWN:{status or 'MISSING'}")
    if parse_timestamp(record.get("created_at")) is None:
        reasons.append("PRODUCTION_CREATED_AT_INVALID")
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("PRODUCTION_REASON_CODES_MALFORMED")
    if contains_sensitive_marker(record):
        reasons.append("PRODUCTION_SENSITIVE_PAYLOAD_BLOCKED")
    if record.get("readiness_hash") and record.get("readiness_hash") != compute_readiness_hash(record):
        return ProductionReadinessValidation(False, "TAMPER_DETECTED", ("PRODUCTION_READINESS_HASH_MISMATCH",))
    status = "BLOCKED" if reasons else str(record.get("readiness_status", "BLOCKED"))
    return ProductionReadinessValidation(not reasons and status == "READY", status, tuple(sorted(set(reasons))))


def build_production_readiness_record(
    *,
    readiness_id: str,
    environment_id: str,
    tenant_id: str,
    policy_hash: str,
    audit_hash: str,
    evidence_hash: str,
    lineage_hash: str,
    backup_status: str,
    recovery_status: str,
    runbook_status: str,
    release_status: str,
    readiness_status: str,
    created_at: str,
    policy_version: str = PRODUCTION_READINESS_POLICY_VERSION,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = True,
) -> dict[str, Any]:
    record = {
        "schema": PRODUCTION_READINESS_SCHEMA,
        "readiness_id": str(readiness_id),
        "environment_id": str(environment_id),
        "tenant_id": str(tenant_id),
        "policy_version": str(policy_version),
        "policy_hash": str(policy_hash),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "lineage_hash": str(lineage_hash),
        "backup_status": str(backup_status),
        "recovery_status": str(recovery_status),
        "runbook_status": str(runbook_status),
        "release_status": str(release_status),
        "readiness_status": str(readiness_status),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "created_at": str(created_at),
        "fail_closed": bool(fail_closed),
        "readiness_hash": "",
    }
    record["readiness_hash"] = compute_readiness_hash(record)
    return record
