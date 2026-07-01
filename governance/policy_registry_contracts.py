from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


POLICY_RECORD_SCHEMA = "usbay.policy.record.v1"
POLICY_VERSION_SCHEMA = "usbay.policy.version.v1"
POLICY_PROMOTION_SCHEMA = "usbay.policy.promotion.v1"
POLICY_DEPRECATION_SCHEMA = "usbay.policy.deprecation.v1"
POLICY_AUDIT_RECORD_SCHEMA = "usbay.policy.audit_record.v1"
POLICY_REGISTRY_POLICY_VERSION = "usbay.pb-policy-registry.governed-policy-lifecycle.v1"

POLICY_STATES = frozenset({"DRAFT", "REVIEW_REQUIRED", "APPROVED", "ACTIVE", "DEPRECATED", "RETIRED"})
REQUIRED_POLICY_FIELDS = (
    "policy_id",
    "policy_name",
    "policy_version",
    "policy_hash",
    "parent_version",
    "status",
    "created_at",
    "approved_at",
    "approved_by",
    "audit_hash",
    "lineage_hash",
    "reason_codes",
)
SENSITIVE_MARKERS = ("secret", "token", "cookie", "api_key", "private_key", "password", "authorization", "credential")


@dataclass(frozen=True)
class PolicyValidation:
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


def canonical_policy_payload(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy_id": str(policy.get("policy_id", "")),
        "policy_name": str(policy.get("policy_name", "")),
        "policy_version": str(policy.get("policy_version", "")),
        "parent_version": str(policy.get("parent_version", "")),
        "status": str(policy.get("status", "")),
        "created_at": str(policy.get("created_at", "")),
        "approved_at": str(policy.get("approved_at", "")),
        "approved_by": str(policy.get("approved_by", "")),
        "audit_hash": str(policy.get("audit_hash", "")),
        "lineage_hash": str(policy.get("lineage_hash", "")),
        "reason_codes": sorted(str(code) for code in policy.get("reason_codes", []) if code),
    }


def compute_policy_hash(policy: dict[str, Any]) -> str:
    return sha256_json(canonical_policy_payload(policy))


def validate_policy_record(policy: dict[str, Any] | None) -> PolicyValidation:
    if not isinstance(policy, dict):
        return PolicyValidation(False, "BLOCKED", ("POLICY_RECORD_MALFORMED",))
    reasons: list[str] = []
    if policy.get("schema") != POLICY_RECORD_SCHEMA:
        reasons.append("POLICY_RECORD_SCHEMA_INVALID")
    for field in REQUIRED_POLICY_FIELDS:
        if policy.get(field) in ("", None):
            if field in {"approved_at", "approved_by"} and policy.get("status") in {"DRAFT", "REVIEW_REQUIRED"}:
                continue
            if field == "parent_version" and policy.get("policy_version") in {"v1", "1.0.0", "1"}:
                continue
            reasons.append(f"POLICY_{field.upper()}_MISSING")
    status = str(policy.get("status", ""))
    if status not in POLICY_STATES:
        reasons.append(f"POLICY_STATUS_UNKNOWN:{status or 'MISSING'}")
    if status in {"APPROVED", "ACTIVE", "DEPRECATED", "RETIRED"}:
        if not str(policy.get("approved_at", "")).strip():
            reasons.append("POLICY_APPROVED_AT_MISSING")
        if not str(policy.get("approved_by", "")).strip():
            reasons.append("POLICY_APPROVED_BY_MISSING")
    if parse_timestamp(policy.get("created_at")) is None:
        reasons.append("POLICY_CREATED_AT_INVALID")
    if policy.get("approved_at") and parse_timestamp(policy.get("approved_at")) is None:
        reasons.append("POLICY_APPROVED_AT_INVALID")
    if not isinstance(policy.get("reason_codes"), list):
        reasons.append("POLICY_REASON_CODES_MALFORMED")
    if contains_sensitive_marker(policy):
        reasons.append("POLICY_SENSITIVE_PAYLOAD_BLOCKED")
    expected_hash = compute_policy_hash(policy)
    if str(policy.get("policy_hash", "")) and policy.get("policy_hash") != expected_hash:
        return PolicyValidation(False, "TAMPER_DETECTED", ("POLICY_HASH_MISMATCH",))
    status_value = "BLOCKED" if reasons else "VERIFIED"
    return PolicyValidation(not reasons, status_value, tuple(sorted(set(reasons))))


def build_policy_record(
    *,
    policy_id: str,
    policy_name: str,
    policy_version: str,
    parent_version: str = "",
    status: str,
    created_at: str,
    approved_at: str = "",
    approved_by: str = "",
    audit_hash: str,
    lineage_hash: str,
    reason_codes: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    record = {
        "schema": POLICY_RECORD_SCHEMA,
        "policy_id": str(policy_id),
        "policy_name": str(policy_name),
        "policy_version": str(policy_version),
        "policy_hash": "",
        "parent_version": str(parent_version),
        "status": str(status),
        "created_at": str(created_at),
        "approved_at": str(approved_at),
        "approved_by": str(approved_by),
        "audit_hash": str(audit_hash),
        "lineage_hash": str(lineage_hash),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
    }
    record["policy_hash"] = compute_policy_hash(record)
    return record


def build_policy_audit_record(*, policy: dict[str, Any] | None, action: str, reason_codes: list[str] | tuple[str, ...]) -> dict[str, Any]:
    safe = policy if isinstance(policy, dict) else {}
    record = {
        "schema": POLICY_AUDIT_RECORD_SCHEMA,
        "policy_id": str(safe.get("policy_id", "")),
        "policy_version": str(safe.get("policy_version", "")),
        "action": str(action),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "audit_hash": "",
        "lineage_hash": str(safe.get("lineage_hash", "")),
        "auto_approved": False,
        "auto_promoted": False,
        "auto_activated": False,
        "auto_retired": False,
    }
    record["audit_hash"] = sha256_json(record | {"audit_hash": ""})
    return record
