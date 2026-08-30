from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.execution_contracts import sha256_json


API_SECURITY_RECORD_SCHEMA = "usbay.api.security.record.v1"
API_INVENTORY_SCHEMA = "usbay.api.inventory.v1"
API_ACCESS_CONTROL_SCHEMA = "usbay.api.access_control.v1"
API_RATE_LIMIT_SCHEMA = "usbay.api.rate_limit.v1"
API_INPUT_VALIDATION_SCHEMA = "usbay.api.input_validation.v1"
API_LINEAGE_SCHEMA = "usbay.api.lineage.v1"
API_SECURITY_POLICY_VERSION = "usbay.pb-api-security.governed-api-security.v1"

API_CLASSIFICATIONS = frozenset({"INTERNAL", "CUSTOMER", "ADMIN", "EXTERNAL", "SENSITIVE"})
REASON_CODES = frozenset(
    {
        "UNKNOWN_API",
        "MISSING_API_INVENTORY",
        "MISSING_CLASSIFICATION",
        "MISSING_ACCESS_CONTROL",
        "MISSING_RATE_LIMIT_POLICY",
        "MISSING_INPUT_VALIDATION_POLICY",
        "MISSING_AUDIT_LINKAGE",
        "MISSING_EVIDENCE_LINKAGE",
        "CROSS_TENANT_API_ACCESS",
        "SENSITIVE_DATA_EXPOSURE",
        "SSRF_RISK_DETECTED",
        "GOVERNANCE_BYPASS_ATTEMPT",
        "EXTERNAL_API_NOT_GOVERNED",
    }
)
REQUIRED_API_FIELDS = (
    "api_id",
    "tenant_id",
    "workspace_id",
    "license_entitlement",
    "classification",
    "inventory_record",
    "access_control_policy",
    "rate_limit_policy",
    "input_validation_policy",
    "audit_hash",
    "evidence_hash",
    "lineage_hash",
    "policy_version",
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
class ApiSecurityValidation:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reason_codes": list(self.reason_codes)}


def contains_sensitive_marker(value: Any) -> bool:
    if isinstance(value, dict):
        text = " ".join(str(item).lower() for pair in value.items() for item in pair)
    elif isinstance(value, list):
        text = " ".join(str(item).lower() for item in value)
    else:
        text = str(value).lower()
    return any(marker in text for marker in SENSITIVE_MARKERS)


def canonical_api_security_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "api_id": str(record.get("api_id", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "workspace_id": str(record.get("workspace_id", "")),
        "license_entitlement": record.get("license_entitlement") is True,
        "classification": str(record.get("classification", "")),
        "inventory_record": record.get("inventory_record") is True,
        "access_control_policy": record.get("access_control_policy") is True,
        "rate_limit_policy": record.get("rate_limit_policy") is True,
        "input_validation_policy": record.get("input_validation_policy") is True,
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "policy_version": str(record.get("policy_version", "")),
        "external_api_governed": record.get("external_api_governed") is True,
        "ssrf_risk": record.get("ssrf_risk") is True,
        "governance_bypass": record.get("governance_bypass") is True,
        "sensitive_data_exposure": record.get("sensitive_data_exposure") is True,
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_api_security_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_api_security_payload(record))


def validate_api_security_record(record: dict[str, Any] | None) -> ApiSecurityValidation:
    if not isinstance(record, dict):
        return ApiSecurityValidation(False, "BLOCKED", ("UNKNOWN_API",))
    reasons: list[str] = []
    if record.get("schema") != API_SECURITY_RECORD_SCHEMA:
        reasons.append("UNKNOWN_API")
    for field in REQUIRED_API_FIELDS:
        if record.get(field) in ("", None):
            reasons.append(f"API_SECURITY_{field.upper()}_MISSING")
    if not str(record.get("api_id", "")).strip():
        reasons.append("UNKNOWN_API")
    if record.get("inventory_record") is not True:
        reasons.append("MISSING_API_INVENTORY")
    if str(record.get("classification", "")) not in API_CLASSIFICATIONS:
        reasons.append("MISSING_CLASSIFICATION")
    if record.get("access_control_policy") is not True:
        reasons.append("MISSING_ACCESS_CONTROL")
    if record.get("rate_limit_policy") is not True:
        reasons.append("MISSING_RATE_LIMIT_POLICY")
    if record.get("input_validation_policy") is not True:
        reasons.append("MISSING_INPUT_VALIDATION_POLICY")
    if not str(record.get("audit_hash", "")).strip():
        reasons.append("MISSING_AUDIT_LINKAGE")
    if not str(record.get("evidence_hash", "")).strip():
        reasons.append("MISSING_EVIDENCE_LINKAGE")
    if not str(record.get("lineage_hash", "")).strip():
        reasons.append("MISSING_API_INVENTORY")
    if record.get("license_entitlement") is not True:
        reasons.append("GOVERNANCE_BYPASS_ATTEMPT")
    if record.get("sensitive_data_exposure") is True or contains_sensitive_marker(record):
        reasons.append("SENSITIVE_DATA_EXPOSURE")
    if record.get("ssrf_risk") is True:
        reasons.append("SSRF_RISK_DETECTED")
    if record.get("governance_bypass") is True:
        reasons.append("GOVERNANCE_BYPASS_ATTEMPT")
    if record.get("classification") == "EXTERNAL" and record.get("external_api_governed") is not True:
        reasons.append("EXTERNAL_API_NOT_GOVERNED")
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("API_SECURITY_REASON_CODES_MALFORMED")
    if record.get("api_security_hash") and record.get("api_security_hash") != compute_api_security_hash(record):
        return ApiSecurityValidation(False, "TAMPER_DETECTED", ("GOVERNANCE_BYPASS_ATTEMPT",))
    status = "BLOCKED" if reasons else "GOVERNED"
    return ApiSecurityValidation(not reasons, status, tuple(sorted(set(reasons))))


def build_api_security_record(
    *,
    api_id: str,
    tenant_id: str,
    workspace_id: str,
    license_entitlement: bool,
    classification: str,
    inventory_record: bool,
    access_control_policy: bool,
    rate_limit_policy: bool,
    input_validation_policy: bool,
    audit_hash: str,
    evidence_hash: str,
    lineage_hash: str,
    policy_version: str,
    external_api_governed: bool = True,
    ssrf_risk: bool = False,
    governance_bypass: bool = False,
    sensitive_data_exposure: bool = False,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = False,
) -> dict[str, Any]:
    record = {
        "schema": API_SECURITY_RECORD_SCHEMA,
        "api_id": str(api_id),
        "tenant_id": str(tenant_id),
        "workspace_id": str(workspace_id),
        "license_entitlement": bool(license_entitlement),
        "classification": str(classification),
        "inventory_record": bool(inventory_record),
        "access_control_policy": bool(access_control_policy),
        "rate_limit_policy": bool(rate_limit_policy),
        "input_validation_policy": bool(input_validation_policy),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "lineage_hash": str(lineage_hash),
        "policy_version": str(policy_version),
        "external_api_governed": bool(external_api_governed),
        "ssrf_risk": bool(ssrf_risk),
        "governance_bypass": bool(governance_bypass),
        "sensitive_data_exposure": bool(sensitive_data_exposure),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "fail_closed": bool(fail_closed),
        "api_security_hash": "",
    }
    record["api_security_hash"] = compute_api_security_hash(record)
    return record
