from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from governance.customer_onboarding_contracts import CUSTOMER_ONBOARDING_POLICY_VERSION
from governance.hashing import is_sha256_reference, sha256_reference


CONTRACT_VERSION = "usbay.euria.enterprise_intake.v1"
SOURCE_SYSTEM = "EURIA"

INTAKE_RECEIVED = "INTAKE_RECEIVED"
VALIDATING = "VALIDATING"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
APPROVED_FOR_PILOT = "APPROVED_FOR_PILOT"
BLOCKED = "BLOCKED"
EXPIRED = "EXPIRED"
REVOKED = "REVOKED"

ELIGIBLE_FOR_GATEWAY = "ELIGIBLE_FOR_GATEWAY"

EURIA_EXECUTION_AUTHORITY = False
EURIA_POLICY_AUTHORITY = False
EURIA_APPROVAL_AUTHORITY = False
EURIA_DEPLOYMENT_AUTHORITY = False

REQUIRED_CONTRACT_FIELDS = frozenset(
    {
        "contract_version",
        "request_id",
        "created_at",
        "expires_at",
        "tenant_reference",
        "environment_reference",
        "requested_capability",
        "requested_action",
        "risk_classification",
        "policy_reference",
        "human_approval_reference",
        "customer_consent_reference",
        "data_classification",
        "execution_requested",
        "source_system",
    }
)

AUTHORITY_FIELDS = frozenset(
    {
        "EURIA_EXECUTION_AUTHORITY",
        "EURIA_POLICY_AUTHORITY",
        "EURIA_APPROVAL_AUTHORITY",
        "EURIA_DEPLOYMENT_AUTHORITY",
    }
)

ALLOWED_CONTRACT_FIELDS = REQUIRED_CONTRACT_FIELDS | AUTHORITY_FIELDS | frozenset({"contract_hash", "revoked"})

SENSITIVE_MARKERS = (
    "password",
    "secret",
    "credential",
    "api_key",
    "private_key",
    "access_token",
    "refresh_token",
    "cookie",
    "authorization",
    "raw_payload",
    "raw_customer_data",
    "ssn",
)


def build_euria_enterprise_intake_contract(
    *,
    request_id: str,
    created_at: str,
    expires_at: str,
    tenant_reference: str,
    environment_reference: str,
    requested_capability: str,
    requested_action: str,
    risk_classification: str,
    policy_reference: str,
    human_approval_reference: str,
    customer_consent_reference: str,
    data_classification: str,
    execution_requested: bool = False,
    source_system: str = SOURCE_SYSTEM,
) -> dict[str, Any]:
    contract: dict[str, Any] = {
        "contract_version": CONTRACT_VERSION,
        "request_id": str(request_id),
        "created_at": str(created_at),
        "expires_at": str(expires_at),
        "tenant_reference": str(tenant_reference),
        "environment_reference": str(environment_reference),
        "requested_capability": str(requested_capability),
        "requested_action": str(requested_action),
        "risk_classification": str(risk_classification),
        "policy_reference": str(policy_reference),
        "human_approval_reference": str(human_approval_reference),
        "customer_consent_reference": str(customer_consent_reference),
        "data_classification": str(data_classification),
        "execution_requested": bool(execution_requested),
        "source_system": str(source_system),
        "EURIA_EXECUTION_AUTHORITY": EURIA_EXECUTION_AUTHORITY,
        "EURIA_POLICY_AUTHORITY": EURIA_POLICY_AUTHORITY,
        "EURIA_APPROVAL_AUTHORITY": EURIA_APPROVAL_AUTHORITY,
        "EURIA_DEPLOYMENT_AUTHORITY": EURIA_DEPLOYMENT_AUTHORITY,
        "revoked": False,
        "contract_hash": "",
    }
    contract["contract_hash"] = compute_contract_hash(contract)
    return contract


def evaluate_euria_enterprise_intake(
    contract: Mapping[str, Any] | None,
    *,
    human_approval: Mapping[str, Any] | None = None,
    policy_validation: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    timestamp = _utc_now(now)
    reasons = _validate_contract(contract, timestamp)
    status = REVIEW_REQUIRED

    if reasons:
        status = _terminal_status(reasons)
    elif human_approval is None or policy_validation is None:
        reasons.append("HUMAN_APPROVAL_AND_POLICY_VALIDATION_REQUIRED")
        status = REVIEW_REQUIRED
    else:
        approval_reasons = _validate_human_approval(human_approval, contract, timestamp)
        policy_reasons = _validate_policy_validation(policy_validation, contract)
        reasons.extend(approval_reasons)
        reasons.extend(policy_reasons)
        status = BLOCKED if reasons else APPROVED_FOR_PILOT

    decision = {
        "contract_version": CONTRACT_VERSION,
        "request_id": _safe_value(contract, "request_id"),
        "state": status,
        "reason_codes": tuple(sorted(set(reasons))),
        "euria_execution_authority": EURIA_EXECUTION_AUTHORITY,
        "euria_policy_authority": EURIA_POLICY_AUTHORITY,
        "euria_approval_authority": EURIA_APPROVAL_AUTHORITY,
        "euria_deployment_authority": EURIA_DEPLOYMENT_AUTHORITY,
        "policy_brain_request": (
            normalize_policy_brain_request(contract) if isinstance(contract, Mapping) and status in {REVIEW_REQUIRED, APPROVED_FOR_PILOT} else None
        ),
        "execution_eligibility": _execution_eligibility(status),
        "evidence": generate_euria_intake_evidence(contract, status, timestamp),
    }
    return decision


def normalize_policy_brain_request(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "policy_contract_version": CUSTOMER_ONBOARDING_POLICY_VERSION,
        "source_system": SOURCE_SYSTEM,
        "request_id": str(contract.get("request_id", "")),
        "tenant_reference": str(contract.get("tenant_reference", "")),
        "environment_reference": str(contract.get("environment_reference", "")),
        "requested_capability": str(contract.get("requested_capability", "")),
        "requested_action": str(contract.get("requested_action", "")),
        "risk_classification": str(contract.get("risk_classification", "")),
        "policy_reference": str(contract.get("policy_reference", "")),
        "human_approval_reference": str(contract.get("human_approval_reference", "")),
        "customer_consent_reference": str(contract.get("customer_consent_reference", "")),
        "execution_requested": contract.get("execution_requested") is True,
        "policy_brain_authoritative": True,
        "euria_policy_authority": False,
    }


def generate_euria_intake_evidence(
    contract: Mapping[str, Any] | None,
    decision: str,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    issued_at = _utc_now(timestamp).isoformat().replace("+00:00", "Z")
    contract_hash = compute_contract_hash(contract) if isinstance(contract, Mapping) else sha256_reference({"missing": True})
    evidence = {
        "request_id": _safe_value(contract, "request_id"),
        "contract_version": CONTRACT_VERSION,
        "decision": str(decision),
        "policy_reference": _safe_value(contract, "policy_reference"),
        "human_approval_reference": _safe_value(contract, "human_approval_reference"),
        "timestamp": issued_at,
        "contract_hash": contract_hash,
        "decision_hash": "",
    }
    evidence["decision_hash"] = sha256_reference({key: value for key, value in evidence.items() if key != "decision_hash"})
    return evidence


def compute_contract_hash(contract: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in contract.items() if key != "contract_hash"}
    return sha256_reference(payload)


def _validate_contract(contract: Mapping[str, Any] | None, now: datetime) -> list[str]:
    if not isinstance(contract, Mapping):
        return ["CONTRACT_MALFORMED"]
    reasons: list[str] = []
    fields = set(contract.keys())
    missing = REQUIRED_CONTRACT_FIELDS - fields
    if missing:
        reasons.extend(f"{field.upper()}_MISSING" for field in sorted(missing))
    unexpected = fields - ALLOWED_CONTRACT_FIELDS
    if unexpected:
        reasons.extend(f"UNAUTHORIZED_FIELD:{field}" for field in sorted(unexpected))
    if contract.get("contract_version") != CONTRACT_VERSION:
        reasons.append("CONTRACT_VERSION_INVALID")
    if contract.get("source_system") != SOURCE_SYSTEM:
        reasons.append("SOURCE_SYSTEM_INVALID")
    if contract.get("execution_requested") is not False:
        reasons.append("EXECUTION_REQUESTED_BLOCKED")
    for field in ("tenant_reference", "environment_reference", "policy_reference", "human_approval_reference", "customer_consent_reference"):
        if field in contract and not is_sha256_reference(contract.get(field)):
            reasons.append(f"{field.upper()}_INVALID")
    for field in ("request_id", "requested_capability", "requested_action", "risk_classification", "data_classification"):
        if not isinstance(contract.get(field), str) or not str(contract.get(field, "")).strip():
            reasons.append(f"{field.upper()}_MISSING")
    if _contains_sensitive_marker(contract):
        reasons.append("SENSITIVE_DATA_FORBIDDEN")
    for authority_field in AUTHORITY_FIELDS:
        if contract.get(authority_field, False) is not False:
            reasons.append(f"{authority_field}_OVERRIDE_BLOCKED")
    created_at = _parse_timestamp(contract.get("created_at"))
    expires_at = _parse_timestamp(contract.get("expires_at"))
    if created_at is None:
        reasons.append("CREATED_AT_INVALID")
    if expires_at is None:
        reasons.append("EXPIRES_AT_INVALID")
    elif expires_at <= now:
        reasons.append("CONTRACT_EXPIRED")
    if created_at is not None and expires_at is not None and expires_at <= created_at:
        reasons.append("CONTRACT_TIMESTAMP_ORDER_INVALID")
    if contract.get("revoked") is True:
        reasons.append("CONTRACT_REVOKED")
    if contract.get("contract_hash") and contract.get("contract_hash") != compute_contract_hash(contract):
        reasons.append("CONTRACT_HASH_MISMATCH")
    return reasons


def _validate_human_approval(approval: Mapping[str, Any], contract: Mapping[str, Any], now: datetime) -> list[str]:
    reasons: list[str] = []
    if not isinstance(approval, Mapping):
        return ["HUMAN_APPROVAL_MALFORMED"]
    if approval.get("approved") is not True:
        reasons.append("HUMAN_APPROVAL_NOT_APPROVED")
    if approval.get("ai_generated_only") is not False:
        reasons.append("AI_GENERATED_APPROVAL_BLOCKED")
    if approval.get("revoked") is True:
        reasons.append("HUMAN_APPROVAL_REVOKED")
    bindings = {
        "request_id": contract.get("request_id"),
        "tenant_reference": contract.get("tenant_reference"),
        "environment_reference": contract.get("environment_reference"),
        "policy_reference": contract.get("policy_reference"),
        "human_approval_reference": contract.get("human_approval_reference"),
    }
    for field, expected in bindings.items():
        if approval.get(field) != expected:
            reasons.append(f"HUMAN_APPROVAL_{field.upper()}_MISMATCH")
    issued_at = _parse_timestamp(approval.get("issued_at"))
    expires_at = _parse_timestamp(approval.get("expires_at"))
    if issued_at is None:
        reasons.append("HUMAN_APPROVAL_ISSUED_AT_INVALID")
    if expires_at is None:
        reasons.append("HUMAN_APPROVAL_EXPIRES_AT_INVALID")
    elif expires_at <= now:
        reasons.append("HUMAN_APPROVAL_EXPIRED")
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        reasons.append("HUMAN_APPROVAL_TIMESTAMP_ORDER_INVALID")
    return reasons


def _validate_policy_validation(policy_validation: Mapping[str, Any], contract: Mapping[str, Any]) -> list[str]:
    if not isinstance(policy_validation, Mapping):
        return ["POLICY_VALIDATION_MALFORMED"]
    reasons: list[str] = []
    if policy_validation.get("policy_brain_authoritative") is not True:
        reasons.append("POLICY_BRAIN_VALIDATION_MISSING")
    if policy_validation.get("policy_reference") != contract.get("policy_reference"):
        reasons.append("POLICY_VALIDATION_REFERENCE_MISMATCH")
    if policy_validation.get("decision") not in {"ALLOW", "APPROVED_FOR_PILOT"}:
        reasons.append("POLICY_VALIDATION_NOT_APPROVED")
    if policy_validation.get("execution_authorized") is True:
        reasons.append("POLICY_VALIDATION_EXECUTION_AUTHORITY_BLOCKED")
    return reasons


def _execution_eligibility(status: str) -> str:
    if status == APPROVED_FOR_PILOT:
        return ELIGIBLE_FOR_GATEWAY
    if status == REVIEW_REQUIRED:
        return REVIEW_REQUIRED
    return BLOCKED


def _terminal_status(reasons: list[str]) -> str:
    if "CONTRACT_REVOKED" in reasons:
        return REVOKED
    if "CONTRACT_EXPIRED" in reasons:
        return EXPIRED
    return BLOCKED


def _safe_value(contract: Mapping[str, Any] | None, field: str) -> str:
    if not isinstance(contract, Mapping):
        return ""
    value = contract.get(field)
    return value if isinstance(value, str) else ""


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _contains_sensitive_marker(value: Any) -> bool:
    if isinstance(value, Mapping):
        text = " ".join(str(item).lower() for pair in value.items() for item in pair)
    elif isinstance(value, list | tuple | set):
        text = " ".join(str(item).lower() for item in value)
    else:
        text = str(value).lower()
    return any(marker in text for marker in SENSITIVE_MARKERS)
