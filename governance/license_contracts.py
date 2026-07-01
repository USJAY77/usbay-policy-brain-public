from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


LICENSE_RECORD_SCHEMA = "usbay.license.record.v1"
LICENSE_ENTITLEMENT_SCHEMA = "usbay.license.entitlement.v1"
LICENSE_VALIDATION_SCHEMA = "usbay.license.validation.v1"
LICENSE_LIFECYCLE_SCHEMA = "usbay.license.lifecycle.v1"
LICENSE_POLICY_VERSION = "usbay.pb-license-governance.governed-license-entitlement.v1"

SUPPORTED_LICENSE_TIERS = frozenset({"STARTER", "ENTERPRISE", "CRITICAL_INFRA", "SOVEREIGN"})
ALLOWED_LICENSE_STATES = frozenset({"PENDING", "ACTIVE", "SUSPENDED", "EXPIRED", "REVOKED", "BLOCKED"})
FAIL_CLOSED_REASON_CODES = frozenset(
    {
        "MISSING_LICENSE",
        "EXPIRED_LICENSE",
        "SUSPENDED_LICENSE",
        "REVOKED_LICENSE",
        "UNKNOWN_LICENSE_TIER",
        "TENANT_MISMATCH",
        "WORKSPACE_MISMATCH",
        "ENTITLEMENT_MISMATCH",
        "CAPABILITY_NOT_LICENSED",
        "SOVEREIGN_LICENSE_REQUIRED",
        "AUDIT_EXPORT_NOT_LICENSED",
        "GOVERNANCE_MODULE_NOT_LICENSED",
    }
)
REQUIRED_LICENSE_FIELDS = (
    "license_id",
    "customer_id",
    "tenant_id",
    "workspace_id",
    "license_tier",
    "license_state",
    "entitlements",
    "policy_version",
    "audit_hash",
    "evidence_hash",
    "issued_at",
    "expires_at",
    "reason_codes",
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
    "credential",
    "raw_payload",
    "raw_screenshot",
)


@dataclass(frozen=True)
class LicenseValidation:
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


def canonical_license_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "license_id": str(record.get("license_id", "")),
        "customer_id": str(record.get("customer_id", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "workspace_id": str(record.get("workspace_id", "")),
        "license_tier": str(record.get("license_tier", "")),
        "license_state": str(record.get("license_state", "")),
        "entitlements": sorted(str(item) for item in record.get("entitlements", []) if item),
        "policy_version": str(record.get("policy_version", "")),
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "issued_at": str(record.get("issued_at", "")),
        "expires_at": str(record.get("expires_at", "")),
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_license_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_license_payload(record))


def validate_license_record(record: dict[str, Any] | None, *, now: datetime | None = None) -> LicenseValidation:
    if not isinstance(record, dict):
        return LicenseValidation(False, "BLOCKED", ("MISSING_LICENSE",))
    reasons: list[str] = []
    if record.get("schema") != LICENSE_RECORD_SCHEMA:
        reasons.append("MISSING_LICENSE")
    for field in REQUIRED_LICENSE_FIELDS:
        if record.get(field) in ("", None):
            reasons.append(f"LICENSE_{field.upper()}_MISSING")
    tier = str(record.get("license_tier", ""))
    if tier not in SUPPORTED_LICENSE_TIERS:
        reasons.append("UNKNOWN_LICENSE_TIER")
    state = str(record.get("license_state", ""))
    if state not in ALLOWED_LICENSE_STATES:
        reasons.append(f"LICENSE_STATE_UNKNOWN:{state or 'MISSING'}")
    if state == "SUSPENDED":
        reasons.append("SUSPENDED_LICENSE")
    if state == "EXPIRED":
        reasons.append("EXPIRED_LICENSE")
    if state == "REVOKED":
        reasons.append("REVOKED_LICENSE")
    if not isinstance(record.get("entitlements"), list):
        reasons.append("ENTITLEMENT_MISMATCH")
    if not str(record.get("policy_version", "")).strip():
        reasons.append("GOVERNANCE_MODULE_NOT_LICENSED")
    if not str(record.get("audit_hash", "")).strip():
        reasons.append("AUDIT_EXPORT_NOT_LICENSED")
    if not str(record.get("evidence_hash", "")).strip():
        reasons.append("ENTITLEMENT_MISMATCH")
    if parse_timestamp(record.get("issued_at")) is None:
        reasons.append("LICENSE_ISSUED_AT_INVALID")
    expires_at = parse_timestamp(record.get("expires_at"))
    if expires_at is None:
        reasons.append("EXPIRED_LICENSE")
    else:
        effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if expires_at <= effective_now:
            reasons.append("EXPIRED_LICENSE")
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("LICENSE_REASON_CODES_MALFORMED")
    if contains_sensitive_marker(record):
        reasons.append("SENSITIVE_DATA_LOGGING_FORBIDDEN")
    if record.get("license_hash") and record.get("license_hash") != compute_license_hash(record):
        return LicenseValidation(False, "TAMPER_DETECTED", ("LICENSE_HASH_MISMATCH",))
    status = "BLOCKED" if reasons else state
    return LicenseValidation(not reasons and status == "ACTIVE", status, tuple(sorted(set(reasons))))


def build_license_record(
    *,
    license_id: str,
    customer_id: str,
    tenant_id: str,
    workspace_id: str,
    license_tier: str,
    license_state: str,
    entitlements: list[str] | tuple[str, ...],
    policy_version: str,
    audit_hash: str,
    evidence_hash: str,
    issued_at: str,
    expires_at: str,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = True,
) -> dict[str, Any]:
    record = {
        "schema": LICENSE_RECORD_SCHEMA,
        "license_id": str(license_id),
        "customer_id": str(customer_id),
        "tenant_id": str(tenant_id),
        "workspace_id": str(workspace_id),
        "license_tier": str(license_tier),
        "license_state": str(license_state),
        "entitlements": sorted(str(item) for item in entitlements if item),
        "policy_version": str(policy_version),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "issued_at": str(issued_at),
        "expires_at": str(expires_at),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "fail_closed": bool(fail_closed),
        "license_hash": "",
    }
    record["license_hash"] = compute_license_hash(record)
    return record
