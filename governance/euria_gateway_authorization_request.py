from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from governance.euria_enterprise_intake import (
    EURIA_APPROVAL_AUTHORITY,
    EURIA_DEPLOYMENT_AUTHORITY,
    EURIA_EXECUTION_AUTHORITY,
    EURIA_POLICY_AUTHORITY,
)
from governance.euria_pilot_activation_gateway_readiness import (
    BLOCKED,
    CONTRACT_VERSION as ACTIVATION_CONTRACT_VERSION,
    EXPIRED,
    REVOKED,
    build_pilot_activation_request,
    compute_activation_request_hash,
    evaluate_pilot_activation_gateway_readiness,
    verify_pilot_activation_evidence,
)
from governance.hashing import is_sha256_reference, sha256_reference


CONTRACT_VERSION = "usbay.euria.gateway_authorization_request.v1"
EVIDENCE_VERSION = "usbay.euria.gateway_authorization_request.evidence.v1"
GATEWAY_CONSUMER_CONTRACT_VERSION = "usbay.enforcement_gateway.authorization_request.v1"

GATEWAY_REQUEST_PENDING = "GATEWAY_REQUEST_PENDING"
GATEWAY_REQUEST_VALIDATED = "GATEWAY_REQUEST_VALIDATED"
GATEWAY_REQUEST_BLOCKED = "GATEWAY_REQUEST_BLOCKED"
GATEWAY_REQUEST_EXPIRED = "GATEWAY_REQUEST_EXPIRED"
GATEWAY_REQUEST_REVOKED = "GATEWAY_REQUEST_REVOKED"

POLICY_BRAIN_EXECUTION_AUTHORITY = False

ALLOWED_STATES = frozenset(
    {
        GATEWAY_REQUEST_PENDING,
        GATEWAY_REQUEST_VALIDATED,
        GATEWAY_REQUEST_BLOCKED,
        GATEWAY_REQUEST_EXPIRED,
        GATEWAY_REQUEST_REVOKED,
    }
)

REQUEST_HASH_FIELDS = (
    "tenant_reference",
    "environment_reference",
    "customer_onboarding_reference",
    "human_approval_reference",
    "policy_reference",
    "policy_hash",
    "pilot_reference",
    "activation_reference",
    "identity_reference",
    "identity_hash",
    "verifier_reference",
    "verifier_hash",
    "attestation_reference",
    "attestation_hash",
    "challenge_reference",
    "nonce_reference",
    "readiness_decision_hash",
    "activation_request_hash",
    "previous_evidence_hash",
    "current_evidence_hash",
    "evidence_chain_reference",
)

SENSITIVE_MARKERS = (
    "pass" + "word",
    "sec" + "ret",
    "cred" + "ential",
    "api" + "_key",
    "private" + "_key",
    "access" + "_token",
    "refresh" + "_token",
    "cook" + "ie",
    "bearer ",
    "raw" + "_payload",
    "raw" + "_customer_data",
    "pro" + "mpt",
    "personal" + "_data",
    "ssn",
)


def evaluate_gateway_authorization_request_contract(
    activation_request: Mapping[str, Any] | None,
    *,
    readiness_context: Mapping[str, Any] | None,
    request_id: str | None = None,
    used_nonce_references: tuple[str, ...] | list[str] | set[str] = (),
    now: datetime | None = None,
) -> dict[str, Any]:
    timestamp = _utc_now(now)
    readiness_probe = evaluate_pilot_activation_gateway_readiness(
        activation_request,
        readiness_context=readiness_context,
        gateway_authorization=None,
        used_nonce_references=used_nonce_references,
        now=timestamp,
    )
    reasons = _activation_prerequisite_reasons(readiness_probe)
    reasons.extend(_validate_request_authority_boundary(activation_request))
    reasons.extend(_validate_context_authority_boundary(readiness_context))
    if _contains_sensitive_marker({"activation_request": activation_request, "readiness_context": readiness_context}):
        reasons.append("SENSITIVE_DATA_FORBIDDEN")

    state = _terminal_state(activation_request, reasons, timestamp)
    gateway_request = (
        _build_gateway_authorization_request(
            activation_request,
            readiness_probe,
            request_id=request_id,
            timestamp=timestamp,
        )
        if state == GATEWAY_REQUEST_VALIDATED
        else None
    )
    evidence = generate_gateway_authorization_request_evidence(
        activation_request,
        readiness_probe,
        gateway_request,
        state,
        reasons,
        timestamp,
    )
    return {
        "contract_version": CONTRACT_VERSION,
        "state": state,
        "gateway_request_created": gateway_request is not None,
        "gateway_authorization_request": gateway_request,
        "execution_authorized": False,
        "runtime_allow": False,
        "policy_brain_execution_authority": POLICY_BRAIN_EXECUTION_AUTHORITY,
        "euria_execution_authority": EURIA_EXECUTION_AUTHORITY,
        "euria_policy_authority": EURIA_POLICY_AUTHORITY,
        "euria_approval_authority": EURIA_APPROVAL_AUTHORITY,
        "euria_deployment_authority": EURIA_DEPLOYMENT_AUTHORITY,
        "enforcement_gateway_final_authority": True,
        "gateway_bypass": False,
        "provider_execution": False,
        "production_activation": False,
        "deployment_authorized": False,
        "reason_codes": tuple(sorted(set(str(reason) for reason in reasons if reason))),
        "activation_state": str(readiness_probe.get("state", BLOCKED)),
        "evidence": evidence,
    }


def build_gateway_authorization_request(
    activation_request: Mapping[str, Any] | None,
    *,
    readiness_context: Mapping[str, Any] | None,
    request_id: str | None = None,
    used_nonce_references: tuple[str, ...] | list[str] | set[str] = (),
    now: datetime | None = None,
) -> dict[str, Any]:
    result = evaluate_gateway_authorization_request_contract(
        activation_request,
        readiness_context=readiness_context,
        request_id=request_id,
        used_nonce_references=used_nonce_references,
        now=now,
    )
    request = result.get("gateway_authorization_request")
    if isinstance(request, Mapping):
        return dict(request)
    return {}


def verify_gateway_authorization_request(request: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        return {"valid": False, "reason_codes": ("GATEWAY_AUTHORIZATION_REQUEST_MISSING",)}
    reasons: list[str] = []
    if request.get("contract_version") != CONTRACT_VERSION:
        reasons.append("GATEWAY_REQUEST_CONTRACT_VERSION_INVALID")
    if request.get("gateway_contract_version") != GATEWAY_CONSUMER_CONTRACT_VERSION:
        reasons.append("GATEWAY_CONSUMER_CONTRACT_VERSION_INVALID")
    if request.get("state") != GATEWAY_REQUEST_VALIDATED:
        reasons.append("GATEWAY_REQUEST_STATE_INVALID")
    if request.get("execution_authorized") is not False:
        reasons.append("GATEWAY_REQUEST_EXECUTION_AUTHORITY_FORBIDDEN")
    if request.get("runtime_allow") is not False:
        reasons.append("GATEWAY_REQUEST_RUNTIME_ALLOW_FORBIDDEN")
    if request.get("policy_brain_execution_authority") is not False:
        reasons.append("POLICY_BRAIN_EXECUTION_AUTHORITY_FORBIDDEN")
    for field in REQUEST_HASH_FIELDS + ("request_hash", "decision_correlation_reference"):
        if not is_sha256_reference(request.get(field)):
            reasons.append(f"{field.upper()}_INVALID")
    if request.get("request_hash") and request.get("request_hash") != compute_gateway_authorization_request_hash(request):
        reasons.append("GATEWAY_AUTHORIZATION_REQUEST_HASH_MISMATCH")
    issued = _parse_timestamp(request.get("issued_at"))
    expires = _parse_timestamp(request.get("expires_at"))
    if issued is None:
        reasons.append("GATEWAY_REQUEST_ISSUED_AT_INVALID")
    if expires is None:
        reasons.append("GATEWAY_REQUEST_EXPIRES_AT_INVALID")
    if issued is not None and expires is not None and expires <= issued:
        reasons.append("GATEWAY_REQUEST_TIMESTAMP_ORDER_INVALID")
    if _contains_sensitive_marker(request):
        reasons.append("SENSITIVE_DATA_FORBIDDEN")
    return {"valid": not reasons, "reason_codes": tuple(sorted(set(reasons)))}


def generate_gateway_authorization_request_evidence(
    activation_request: Mapping[str, Any] | None,
    readiness_probe: Mapping[str, Any] | None,
    gateway_request: Mapping[str, Any] | None,
    state: str,
    reasons: list[str] | tuple[str, ...],
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    issued_at = _utc_now(timestamp).isoformat().replace("+00:00", "Z")
    evidence = {
        "evidence_version": EVIDENCE_VERSION,
        "contract_version": CONTRACT_VERSION,
        "request_id": _safe_value(gateway_request, "request_id") or _safe_value(activation_request, "request_id"),
        "tenant_reference": _safe_value(activation_request, "tenant_reference"),
        "environment_reference": _safe_value(activation_request, "environment_reference"),
        "policy_reference": _safe_value(activation_request, "policy_reference"),
        "policy_hash": _safe_value(activation_request, "policy_hash"),
        "human_approval_reference": _safe_value(activation_request, "human_approval_reference"),
        "pilot_reference": _safe_value(activation_request, "pilot_reference"),
        "activation_request_hash": _safe_value(activation_request, "activation_request_hash"),
        "readiness_decision_hash": _safe_value(activation_request, "readiness_decision_hash"),
        "gateway_request_hash": _safe_value(gateway_request, "request_hash"),
        "evidence_chain_reference": _safe_value(activation_request, "evidence_chain_reference"),
        "state": state if state in ALLOWED_STATES else GATEWAY_REQUEST_BLOCKED,
        "reason_codes": sorted(str(reason) for reason in reasons if reason),
        "timestamp": issued_at,
        "execution_authorized": False,
        "runtime_allow": False,
        "enforcement_gateway_final_authority": True,
        "evidence_hash": "",
    }
    evidence["evidence_hash"] = sha256_reference({key: value for key, value in evidence.items() if key != "evidence_hash"})
    return evidence


def verify_gateway_authorization_request_evidence(evidence: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(evidence, Mapping):
        return {"valid": False, "reason_codes": ("GATEWAY_REQUEST_EVIDENCE_MISSING",)}
    reasons: list[str] = []
    if evidence.get("evidence_version") != EVIDENCE_VERSION:
        reasons.append("GATEWAY_REQUEST_EVIDENCE_VERSION_INVALID")
    if evidence.get("contract_version") != CONTRACT_VERSION:
        reasons.append("GATEWAY_REQUEST_EVIDENCE_CONTRACT_VERSION_INVALID")
    if evidence.get("state") not in ALLOWED_STATES:
        reasons.append("GATEWAY_REQUEST_EVIDENCE_STATE_INVALID")
    for field in (
        "tenant_reference",
        "environment_reference",
        "policy_reference",
        "policy_hash",
        "human_approval_reference",
        "pilot_reference",
        "activation_request_hash",
        "readiness_decision_hash",
        "evidence_chain_reference",
        "evidence_hash",
    ):
        if not is_sha256_reference(evidence.get(field)):
            reasons.append(f"GATEWAY_REQUEST_EVIDENCE_{field.upper()}_INVALID")
    gateway_request_hash = evidence.get("gateway_request_hash")
    if gateway_request_hash not in ("", None) and not is_sha256_reference(gateway_request_hash):
        reasons.append("GATEWAY_REQUEST_EVIDENCE_GATEWAY_REQUEST_HASH_INVALID")
    if evidence.get("execution_authorized") is not False or evidence.get("runtime_allow") is not False:
        reasons.append("GATEWAY_REQUEST_EVIDENCE_EXECUTION_AUTHORITY_FORBIDDEN")
    expected = sha256_reference({key: value for key, value in evidence.items() if key != "evidence_hash"})
    if evidence.get("evidence_hash") != expected:
        reasons.append("GATEWAY_REQUEST_EVIDENCE_HASH_MISMATCH")
    if _contains_sensitive_marker(evidence):
        reasons.append("SENSITIVE_DATA_FORBIDDEN")
    return {"valid": not reasons, "reason_codes": tuple(sorted(set(reasons)))}


def compute_gateway_authorization_request_hash(request: Mapping[str, Any]) -> str:
    return sha256_reference({key: value for key, value in request.items() if key != "request_hash"})


def _activation_prerequisite_reasons(readiness_probe: Mapping[str, Any]) -> list[str]:
    reasons = [str(reason) for reason in readiness_probe.get("reason_codes", ())]
    return [reason for reason in reasons if reason != "GATEWAY_AUTHORIZATION_MISSING"]


def _build_gateway_authorization_request(
    activation_request: Mapping[str, Any] | None,
    readiness_probe: Mapping[str, Any],
    *,
    request_id: str | None,
    timestamp: datetime,
) -> dict[str, Any]:
    if not isinstance(activation_request, Mapping):
        return {}
    activation_hash = str(activation_request.get("activation_request_hash", ""))
    evidence = readiness_probe.get("evidence") if isinstance(readiness_probe.get("evidence"), Mapping) else {}
    request = {
        "contract_version": CONTRACT_VERSION,
        "gateway_contract_version": GATEWAY_CONSUMER_CONTRACT_VERSION,
        "request_id": str(request_id or activation_request.get("request_id", "")),
        "tenant_reference": str(activation_request.get("tenant_reference", "")),
        "environment_reference": str(activation_request.get("environment_reference", "")),
        "customer_onboarding_reference": str(activation_request.get("onboarding_reference", "")),
        "human_approval_reference": str(activation_request.get("human_approval_reference", "")),
        "policy_reference": str(activation_request.get("policy_reference", "")),
        "policy_hash": str(activation_request.get("policy_hash", "")),
        "pilot_reference": str(activation_request.get("pilot_reference", "")),
        "activation_reference": activation_hash,
        "identity_reference": str(activation_request.get("identity_reference", "")),
        "identity_hash": str(activation_request.get("identity_hash", "")),
        "verifier_reference": str(activation_request.get("verifier_reference", "")),
        "verifier_hash": str(activation_request.get("verifier_hash", "")),
        "attestation_reference": str(activation_request.get("attestation_reference", "")),
        "attestation_hash": str(activation_request.get("attestation_hash", "")),
        "challenge_reference": str(activation_request.get("challenge_reference", "")),
        "nonce_reference": str(activation_request.get("nonce_reference", "")),
        "issued_at": timestamp.isoformat().replace("+00:00", "Z"),
        "expires_at": str(activation_request.get("expires_at", "")),
        "readiness_decision_hash": str(activation_request.get("readiness_decision_hash", "")),
        "activation_request_hash": activation_hash,
        "previous_evidence_hash": str(evidence.get("evidence_hash", "")),
        "current_evidence_hash": str(evidence.get("evidence_hash", "")),
        "evidence_chain_reference": str(activation_request.get("evidence_chain_reference", "")),
        "decision_correlation_reference": sha256_reference(
            {
                "contract_version": CONTRACT_VERSION,
                "activation_request_hash": activation_hash,
                "readiness_decision_hash": activation_request.get("readiness_decision_hash", ""),
                "policy_hash": activation_request.get("policy_hash", ""),
                "tenant_reference": activation_request.get("tenant_reference", ""),
                "environment_reference": activation_request.get("environment_reference", ""),
            }
        ),
        "state": GATEWAY_REQUEST_VALIDATED,
        "execution_authorized": False,
        "runtime_allow": False,
        "policy_brain_execution_authority": POLICY_BRAIN_EXECUTION_AUTHORITY,
        "enforcement_gateway_final_authority": True,
        "request_hash": "",
    }
    request["request_hash"] = compute_gateway_authorization_request_hash(request)
    return request


def _validate_request_authority_boundary(activation_request: Mapping[str, Any] | None) -> list[str]:
    reasons: list[str] = []
    forbidden_truths = {
        "EURIA_EXECUTION_AUTHORITY": "EURIA_EXECUTION_AUTHORITY_FORBIDDEN",
        "EURIA_POLICY_AUTHORITY": "EURIA_POLICY_AUTHORITY_FORBIDDEN",
        "EURIA_APPROVAL_AUTHORITY": "EURIA_APPROVAL_AUTHORITY_FORBIDDEN",
        "EURIA_DEPLOYMENT_AUTHORITY": "EURIA_DEPLOYMENT_AUTHORITY_FORBIDDEN",
        "POLICY_BRAIN_EXECUTION_AUTHORITY": "POLICY_BRAIN_EXECUTION_AUTHORITY_FORBIDDEN",
        "policy_brain_execution_authority": "POLICY_BRAIN_EXECUTION_AUTHORITY_FORBIDDEN",
        "execution_authorized": "EXECUTION_AUTHORIZATION_FORBIDDEN",
        "runtime_allow": "RUNTIME_ALLOW_FORBIDDEN",
        "gateway_bypass": "GATEWAY_BYPASS_FORBIDDEN",
        "deployment_authorized": "DEPLOYMENT_AUTHORIZATION_FORBIDDEN",
        "production_activation": "PRODUCTION_ACTIVATION_FORBIDDEN",
    }
    for field, reason in forbidden_truths.items():
        if _contains_truthy_key(activation_request, field):
            reasons.append(reason)
    return reasons


def _validate_context_authority_boundary(readiness_context: Mapping[str, Any] | None) -> list[str]:
    return _validate_request_authority_boundary(readiness_context)


def _terminal_state(activation_request: Mapping[str, Any] | None, reasons: list[str], now: datetime) -> str:
    if not reasons:
        return GATEWAY_REQUEST_VALIDATED
    if isinstance(activation_request, Mapping):
        if activation_request.get("revoked") is True:
            return GATEWAY_REQUEST_REVOKED
        expires = _parse_timestamp(activation_request.get("expires_at"))
        if expires is not None and expires <= now:
            return GATEWAY_REQUEST_EXPIRED
    return GATEWAY_REQUEST_BLOCKED


def _contains_truthy_key(value: Any, key: str) -> bool:
    if isinstance(value, Mapping):
        if value.get(key) is True:
            return True
        return any(_contains_truthy_key(item, key) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_truthy_key(item, key) for item in value)
    return False


def _contains_sensitive_marker(value: Any) -> bool:
    if isinstance(value, Mapping):
        text = " ".join(str(item).lower() for pair in value.items() for item in pair)
    elif isinstance(value, (list, tuple, set)):
        text = " ".join(str(item).lower() for item in value)
    else:
        text = str(value).lower()
    return any(marker in text for marker in SENSITIVE_MARKERS)


def _safe_value(value: Mapping[str, Any] | None, field: str) -> str:
    if not isinstance(value, Mapping):
        return ""
    item = value.get(field)
    return item if isinstance(item, str) else ""


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


__all__ = [
    "CONTRACT_VERSION",
    "EVIDENCE_VERSION",
    "GATEWAY_CONSUMER_CONTRACT_VERSION",
    "GATEWAY_REQUEST_BLOCKED",
    "GATEWAY_REQUEST_EXPIRED",
    "GATEWAY_REQUEST_PENDING",
    "GATEWAY_REQUEST_REVOKED",
    "GATEWAY_REQUEST_VALIDATED",
    "POLICY_BRAIN_EXECUTION_AUTHORITY",
    "build_gateway_authorization_request",
    "build_pilot_activation_request",
    "compute_activation_request_hash",
    "compute_gateway_authorization_request_hash",
    "evaluate_gateway_authorization_request_contract",
    "generate_gateway_authorization_request_evidence",
    "verify_gateway_authorization_request",
    "verify_gateway_authorization_request_evidence",
]
