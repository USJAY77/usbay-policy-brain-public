from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


CUSTOMER_ONBOARDING_SCHEMA = "usbay.customer.onboarding.v1"
CUSTOMER_INTAKE_SCHEMA = "usbay.customer.intake.v1"
CUSTOMER_VERIFICATION_SCHEMA = "usbay.customer.verification.v1"
CUSTOMER_READINESS_SCHEMA = "usbay.customer.readiness.v1"
CUSTOMER_ONBOARDING_POLICY_VERSION = "usbay.pb-customer-onboarding.governed-customer-onboarding.v1"

ALLOWED_ONBOARDING_STATES = frozenset(
    {
        "INTAKE_RECEIVED",
        "REVIEW_REQUIRED",
        "VERIFICATION_REQUIRED",
        "READY_FOR_APPROVAL",
        "APPROVED",
        "ACTIVE",
        "REJECTED",
        "BLOCKED",
    }
)
FAIL_CLOSED_REASON_CODES = frozenset(
    {
        "MISSING_TENANT_ID",
        "MISSING_WORKSPACE_ID",
        "MISSING_POLICY_VERSION",
        "MISSING_AUDIT_LINKAGE",
        "MISSING_EVIDENCE_LINKAGE",
        "NO_HUMAN_APPROVAL",
        "MISSING_CUSTOMER_CLASSIFICATION",
        "MISSING_JURISDICTION",
        "MISSING_RISK_CLASSIFICATION",
        "MISSING_WORKSPACE_OWNER",
        "DUPLICATE_TENANT_IDENTITY",
        "CONFLICTING_JURISDICTION",
        "MISSING_DOCUMENT_LIBRARY",
        "MISSING_POLICY_REGISTRY",
        "MISSING_AUDIT_REGISTRY",
        "MISSING_RELEASE_GOVERNANCE",
        "MISSING_TENANT_BOUNDARY",
    }
)
REQUIRED_ONBOARDING_FIELDS = (
    "onboarding_id",
    "tenant_id",
    "workspace_id",
    "policy_version",
    "audit_linkage",
    "evidence_linkage",
    "customer_classification",
    "jurisdiction",
    "risk_classification",
    "workspace_owner",
    "onboarding_state",
    "human_approval",
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
    "credential",
    "raw_payload",
    "raw_screenshot",
)


@dataclass(frozen=True)
class CustomerOnboardingValidation:
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


def canonical_onboarding_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "onboarding_id": str(record.get("onboarding_id", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "workspace_id": str(record.get("workspace_id", "")),
        "policy_version": str(record.get("policy_version", "")),
        "audit_linkage": str(record.get("audit_linkage", "")),
        "evidence_linkage": str(record.get("evidence_linkage", "")),
        "customer_classification": str(record.get("customer_classification", "")),
        "jurisdiction": str(record.get("jurisdiction", "")),
        "risk_classification": str(record.get("risk_classification", "")),
        "workspace_owner": str(record.get("workspace_owner", "")),
        "onboarding_state": str(record.get("onboarding_state", "")),
        "human_approval": record.get("human_approval") is True,
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "created_at": str(record.get("created_at", "")),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_onboarding_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_onboarding_payload(record))


def validate_customer_onboarding(record: dict[str, Any] | None) -> CustomerOnboardingValidation:
    if not isinstance(record, dict):
        return CustomerOnboardingValidation(False, "BLOCKED", ("MISSING_TENANT_ID", "MISSING_WORKSPACE_ID"))
    reasons: list[str] = []
    if record.get("schema") != CUSTOMER_ONBOARDING_SCHEMA:
        reasons.append("CUSTOMER_ONBOARDING_SCHEMA_INVALID")
    for field in REQUIRED_ONBOARDING_FIELDS:
        if record.get(field) in ("", None):
            reasons.append(f"CUSTOMER_ONBOARDING_{field.upper()}_MISSING")
    if not str(record.get("tenant_id", "")).strip():
        reasons.append("MISSING_TENANT_ID")
    if not str(record.get("workspace_id", "")).strip():
        reasons.append("MISSING_WORKSPACE_ID")
    if not str(record.get("policy_version", "")).strip():
        reasons.append("MISSING_POLICY_VERSION")
    if not str(record.get("audit_linkage", "")).strip():
        reasons.append("MISSING_AUDIT_LINKAGE")
    if not str(record.get("evidence_linkage", "")).strip():
        reasons.append("MISSING_EVIDENCE_LINKAGE")
    if record.get("human_approval") is not True:
        reasons.append("NO_HUMAN_APPROVAL")
    if record.get("governance_terms_accepted") is not True:
        reasons.append("GOVERNANCE_TERMS_NOT_ACCEPTED")
    if not str(record.get("customer_classification", "")).strip():
        reasons.append("MISSING_CUSTOMER_CLASSIFICATION")
    if not str(record.get("jurisdiction", "")).strip():
        reasons.append("MISSING_JURISDICTION")
    if not str(record.get("risk_classification", "")).strip():
        reasons.append("MISSING_RISK_CLASSIFICATION")
    if not str(record.get("workspace_owner", "")).strip():
        reasons.append("MISSING_WORKSPACE_OWNER")
    state = str(record.get("onboarding_state", ""))
    if state not in ALLOWED_ONBOARDING_STATES:
        reasons.append(f"CUSTOMER_ONBOARDING_STATE_UNKNOWN:{state or 'MISSING'}")
    if record.get("auto_onboarding") is True:
        reasons.append("AUTO_ONBOARDING_FORBIDDEN")
    if record.get("auto_approval") is True:
        reasons.append("AUTO_APPROVAL_FORBIDDEN")
    if contains_sensitive_marker(record):
        reasons.append("SENSITIVE_DATA_LOGGING_FORBIDDEN")
    if parse_timestamp(record.get("created_at")) is None:
        reasons.append("CUSTOMER_ONBOARDING_CREATED_AT_INVALID")
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("CUSTOMER_ONBOARDING_REASON_CODES_MALFORMED")
    if record.get("onboarding_hash") and record.get("onboarding_hash") != compute_onboarding_hash(record):
        return CustomerOnboardingValidation(False, "TAMPER_DETECTED", ("CUSTOMER_ONBOARDING_HASH_MISMATCH",))
    status = "BLOCKED" if reasons else state
    return CustomerOnboardingValidation(not reasons and status in {"APPROVED", "ACTIVE"}, status, tuple(sorted(set(reasons))))


def build_customer_onboarding_record(
    *,
    onboarding_id: str,
    tenant_id: str,
    workspace_id: str,
    policy_version: str,
    audit_linkage: str,
    evidence_linkage: str,
    customer_classification: str,
    jurisdiction: str,
    risk_classification: str,
    workspace_owner: str,
    onboarding_state: str,
    human_approval: bool,
    created_at: str,
    governance_terms_accepted: bool = True,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = True,
) -> dict[str, Any]:
    record = {
        "schema": CUSTOMER_ONBOARDING_SCHEMA,
        "onboarding_id": str(onboarding_id),
        "tenant_id": str(tenant_id),
        "workspace_id": str(workspace_id),
        "policy_version": str(policy_version),
        "audit_linkage": str(audit_linkage),
        "evidence_linkage": str(evidence_linkage),
        "customer_classification": str(customer_classification),
        "jurisdiction": str(jurisdiction),
        "risk_classification": str(risk_classification),
        "workspace_owner": str(workspace_owner),
        "onboarding_state": str(onboarding_state),
        "human_approval": bool(human_approval),
        "governance_terms_accepted": bool(governance_terms_accepted),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "created_at": str(created_at),
        "fail_closed": bool(fail_closed),
        "onboarding_hash": "",
    }
    record["onboarding_hash"] = compute_onboarding_hash(record)
    return record
