from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


AUDIT_REGISTRY_RECORD_SCHEMA = "usbay.audit_registry.record.v1"
AUDIT_REGISTRY_SCHEMA = "usbay.audit_registry.v1"
AUDIT_LINEAGE_VALIDATION_SCHEMA = "usbay.audit_registry.lineage_validation.v1"
GOVERNANCE_HISTORY_SCHEMA = "usbay.audit_registry.history.v1"
AUDIT_REGISTRY_POLICY_VERSION = "usbay.pb-audit-registry.cryptographic-governance-registry.v1"

REGISTRY_RECORD_TYPES = (
    "Observation",
    "Proposal",
    "Request",
    "Approval",
    "Review",
    "Decision",
    "Work Item",
    "Evidence",
    "Connector Activity",
    "Metric Snapshot",
)
RECORD_TYPE_INDEX = {record_type: index for index, record_type in enumerate(REGISTRY_RECORD_TYPES)}

REQUIRED_REGISTRY_FIELDS = (
    "record_id",
    "record_type",
    "parent_id",
    "previous_hash",
    "current_hash",
    "policy_version",
    "created_at",
    "audit_hash",
    "lineage_hash",
    "source_component",
    "fail_closed",
    "reason_codes",
)

SENSITIVE_MARKERS = ("secret", "token", "cookie", "api_key", "private_key", "password", "authorization", "credential")


@dataclass(frozen=True)
class AuditRegistryValidation:
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
    text = str(value).lower()
    if isinstance(value, dict):
        text = " ".join(str(item).lower() for pair in value.items() for item in pair)
    elif isinstance(value, list):
        text = " ".join(str(item).lower() for item in value)
    return any(marker in text for marker in SENSITIVE_MARKERS)


def canonical_record_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": str(record.get("record_id", "")),
        "record_type": str(record.get("record_type", "")),
        "parent_id": str(record.get("parent_id", "")),
        "previous_hash": str(record.get("previous_hash", "")),
        "policy_version": str(record.get("policy_version", "")),
        "created_at": str(record.get("created_at", "")),
        "audit_hash": str(record.get("audit_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "source_component": str(record.get("source_component", "")),
        "fail_closed": record.get("fail_closed") is True,
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
    }


def compute_record_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_record_payload(record))


def validate_registry_record(record: dict[str, Any] | None) -> AuditRegistryValidation:
    if not isinstance(record, dict):
        return AuditRegistryValidation(False, "BLOCKED", ("AUDIT_REGISTRY_RECORD_MALFORMED",))
    reasons: list[str] = []
    if record.get("schema") != AUDIT_REGISTRY_RECORD_SCHEMA:
        reasons.append("AUDIT_REGISTRY_RECORD_SCHEMA_INVALID")
    for field in REQUIRED_REGISTRY_FIELDS:
        if record.get(field) in ("", None):
            if field == "parent_id" and record.get("record_type") == "Observation":
                continue
            if field == "previous_hash" and record.get("record_type") == "Observation":
                continue
            reasons.append(f"AUDIT_REGISTRY_{field.upper()}_MISSING")
    record_type = str(record.get("record_type", ""))
    if record_type not in RECORD_TYPE_INDEX:
        reasons.append(f"AUDIT_REGISTRY_RECORD_TYPE_UNKNOWN:{record_type or 'MISSING'}")
    if record_type != "Observation" and not str(record.get("parent_id", "")).strip():
        reasons.append("AUDIT_REGISTRY_PARENT_MISSING")
    if parse_timestamp(record.get("created_at")) is None:
        reasons.append("AUDIT_REGISTRY_TIMESTAMP_MISSING_OR_INVALID")
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("AUDIT_REGISTRY_REASON_CODES_MALFORMED")
    if contains_sensitive_marker(record):
        reasons.append("AUDIT_REGISTRY_SENSITIVE_PAYLOAD_BLOCKED")
    expected_hash = compute_record_hash(record)
    if str(record.get("current_hash", "")) and record.get("current_hash") != expected_hash:
        return AuditRegistryValidation(False, "TAMPER_DETECTED", ("AUDIT_REGISTRY_HASH_MISMATCH",))
    status = "BLOCKED" if reasons else "VERIFIED"
    return AuditRegistryValidation(not reasons, status, tuple(sorted(set(reasons))))


def build_registry_record(
    *,
    record_id: str,
    record_type: str,
    parent_id: str = "",
    previous_hash: str = "",
    policy_version: str = AUDIT_REGISTRY_POLICY_VERSION,
    created_at: str,
    audit_hash: str,
    lineage_hash: str,
    source_component: str,
    fail_closed: bool = False,
    reason_codes: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    record = {
        "schema": AUDIT_REGISTRY_RECORD_SCHEMA,
        "record_id": str(record_id),
        "record_type": str(record_type),
        "parent_id": str(parent_id),
        "previous_hash": str(previous_hash),
        "current_hash": "",
        "policy_version": str(policy_version),
        "created_at": str(created_at),
        "audit_hash": str(audit_hash),
        "lineage_hash": str(lineage_hash),
        "source_component": str(source_component),
        "fail_closed": bool(fail_closed),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
    }
    record["current_hash"] = compute_record_hash(record)
    return record
