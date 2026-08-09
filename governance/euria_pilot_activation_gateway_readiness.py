from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from governance.euria_customer_onboarding import PILOT_READY, evaluate_euria_customer_onboarding, verify_onboarding_bridge_evidence
from governance.euria_enterprise_intake import (
    EURIA_APPROVAL_AUTHORITY,
    EURIA_DEPLOYMENT_AUTHORITY,
    EURIA_EXECUTION_AUTHORITY,
    EURIA_POLICY_AUTHORITY,
)
from governance.hashing import is_sha256_reference, sha256_reference


CONTRACT_VERSION = "usbay.euria.pilot_activation_gateway_readiness.v1"
EVIDENCE_VERSION = "usbay.euria.pilot_activation_gateway_readiness.evidence.v1"

ACTIVATION_REQUESTED = "ACTIVATION_REQUESTED"
ACTIVATION_VALIDATING = "ACTIVATION_VALIDATING"
EXECUTION_AUTHORIZED = "EXECUTION_AUTHORIZED"
BLOCKED = "BLOCKED"
EXPIRED = "EXPIRED"
REVOKED = "REVOKED"

PILOT_READINESS_EXECUTION_AUTHORITY = False

ALLOWED_STATES = frozenset(
    {
        PILOT_READY,
        ACTIVATION_REQUESTED,
        ACTIVATION_VALIDATING,
        EXECUTION_AUTHORIZED,
        BLOCKED,
        EXPIRED,
        REVOKED,
    }
)

REQUIRED_REQUEST_FIELDS = (
    "contract_version",
    "request_id",
    "tenant_reference",
    "environment_reference",
    "pilot_reference",
    "onboarding_reference",
    "policy_reference",
    "policy_hash",
    "human_approval_reference",
    "identity_reference",
    "identity_hash",
    "device_reference",
    "device_hash",
    "verifier_reference",
    "verifier_hash",
    "attestation_reference",
    "attestation_hash",
    "readiness_decision_hash",
    "evidence_chain_reference",
    "timestamp",
    "expires_at",
    "nonce_reference",
    "challenge_reference",
    "activation_request_hash",
)

HASH_REFERENCE_FIELDS = (
    "tenant_reference",
    "environment_reference",
    "pilot_reference",
    "onboarding_reference",
    "policy_reference",
    "policy_hash",
    "human_approval_reference",
    "identity_reference",
    "identity_hash",
    "device_reference",
    "device_hash",
    "verifier_reference",
    "verifier_hash",
    "attestation_reference",
    "attestation_hash",
    "readiness_decision_hash",
    "evidence_chain_reference",
    "nonce_reference",
    "challenge_reference",
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
    "author" + "ization",
    "raw" + "_payload",
    "raw" + "_customer_data",
    "pro" + "mpt",
    "personal" + "_data",
    "ssn",
)


def build_pilot_activation_request(
    *,
    request_id: str,
    tenant_reference: str,
    environment_reference: str,
    pilot_reference: str,
    onboarding_reference: str,
    policy_reference: str,
    policy_hash: str,
    human_approval_reference: str,
    identity_reference: str,
    identity_hash: str,
    device_reference: str,
    device_hash: str,
    verifier_reference: str,
    verifier_hash: str,
    attestation_reference: str,
    attestation_hash: str,
    readiness_decision_hash: str,
    evidence_chain_reference: str,
    timestamp: str,
    expires_at: str,
    nonce_reference: str,
    challenge_reference: str,
) -> dict[str, Any]:
    request = {
        "contract_version": CONTRACT_VERSION,
        "request_id": str(request_id),
        "tenant_reference": str(tenant_reference),
        "environment_reference": str(environment_reference),
        "pilot_reference": str(pilot_reference),
        "onboarding_reference": str(onboarding_reference),
        "policy_reference": str(policy_reference),
        "policy_hash": str(policy_hash),
        "human_approval_reference": str(human_approval_reference),
        "identity_reference": str(identity_reference),
        "identity_hash": str(identity_hash),
        "device_reference": str(device_reference),
        "device_hash": str(device_hash),
        "verifier_reference": str(verifier_reference),
        "verifier_hash": str(verifier_hash),
        "attestation_reference": str(attestation_reference),
        "attestation_hash": str(attestation_hash),
        "readiness_decision_hash": str(readiness_decision_hash),
        "evidence_chain_reference": str(evidence_chain_reference),
        "timestamp": str(timestamp),
        "expires_at": str(expires_at),
        "nonce_reference": str(nonce_reference),
        "challenge_reference": str(challenge_reference),
        "activation_request_hash": "",
    }
    request["activation_request_hash"] = compute_activation_request_hash(request)
    return request


def evaluate_pilot_activation_gateway_readiness(
    activation_request: Mapping[str, Any] | None,
    *,
    readiness_context: Mapping[str, Any] | None,
    gateway_authorization: Mapping[str, Any] | None = None,
    used_nonce_references: tuple[str, ...] | list[str] | set[str] = (),
    now: datetime | None = None,
) -> dict[str, Any]:
    timestamp = _utc_now(now)
    reasons = _validate_activation_request(activation_request, timestamp, used_nonce_references)
    readiness_result = _evaluate_readiness_context(readiness_context, timestamp)
    reasons.extend(f"READINESS_{reason}" for reason in readiness_result.get("reason_codes", ()))
    reasons.extend(_validate_readiness_binding(activation_request, readiness_result, readiness_context))
    gateway_reasons = _validate_gateway_authorization(activation_request, readiness_result, gateway_authorization)
    reasons.extend(gateway_reasons)
    reasons.extend(_validate_non_authority_metadata(activation_request))
    reasons.extend(_validate_non_authority_metadata(readiness_context))
    if _contains_sensitive_marker({"activation_request": activation_request, "readiness_context": readiness_context, "gateway": gateway_authorization}):
        reasons.append("SENSITIVE_DATA_FORBIDDEN")

    decision = EXECUTION_AUTHORIZED if not reasons else _terminal_blocked_state(activation_request, timestamp)
    evidence = generate_pilot_activation_evidence(activation_request, readiness_result, gateway_authorization, decision, reasons, timestamp)
    return {
        "contract_version": CONTRACT_VERSION,
        "state": decision,
        "execution_authorized": decision == EXECUTION_AUTHORIZED,
        "gateway_authorized": decision == EXECUTION_AUTHORIZED,
        "gateway_final_authority": True,
        "euria_execution_authority": EURIA_EXECUTION_AUTHORITY,
        "euria_policy_authority": EURIA_POLICY_AUTHORITY,
        "euria_approval_authority": EURIA_APPROVAL_AUTHORITY,
        "euria_deployment_authority": EURIA_DEPLOYMENT_AUTHORITY,
        "pilot_readiness_execution_authority": PILOT_READINESS_EXECUTION_AUTHORITY,
        "provider_execution": False,
        "production_activation": False,
        "deployment_authorized": False,
        "reason_codes": tuple(sorted(set(str(reason) for reason in reasons if reason))),
        "readiness_state": str(readiness_result.get("state", BLOCKED)),
        "evidence": evidence,
    }


def generate_pilot_activation_evidence(
    activation_request: Mapping[str, Any] | None,
    readiness_result: Mapping[str, Any] | None,
    gateway_authorization: Mapping[str, Any] | None,
    decision: str,
    reasons: list[str] | tuple[str, ...],
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    issued_at = _utc_now(timestamp).isoformat().replace("+00:00", "Z")
    evidence = {
        "evidence_version": EVIDENCE_VERSION,
        "activation_contract_version": CONTRACT_VERSION,
        "request_id": _safe_value(activation_request, "request_id"),
        "tenant_reference": _safe_value(activation_request, "tenant_reference"),
        "environment_reference": _safe_value(activation_request, "environment_reference"),
        "pilot_reference": _safe_value(activation_request, "pilot_reference"),
        "policy_reference": _safe_value(activation_request, "policy_reference"),
        "policy_hash": _safe_value(activation_request, "policy_hash"),
        "human_approval_reference": _safe_value(activation_request, "human_approval_reference"),
        "readiness_decision_hash": _safe_value(activation_request, "readiness_decision_hash"),
        "evidence_chain_reference": _safe_value(activation_request, "evidence_chain_reference"),
        "gateway_decision_reference": _safe_value(gateway_authorization, "gateway_decision_hash"),
        "decision": decision if decision in {EXECUTION_AUTHORIZED, BLOCKED, EXPIRED, REVOKED} else BLOCKED,
        "readiness_state": str(readiness_result.get("state", BLOCKED)) if isinstance(readiness_result, Mapping) else BLOCKED,
        "reason_codes": sorted(str(reason) for reason in reasons if reason),
        "timestamp": issued_at,
        "activation_request_hash": _safe_value(activation_request, "activation_request_hash"),
        "evidence_hash": "",
    }
    evidence["evidence_hash"] = sha256_reference({key: value for key, value in evidence.items() if key != "evidence_hash"})
    return evidence


def verify_pilot_activation_evidence(evidence: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(evidence, Mapping):
        return {"valid": False, "reason_codes": ("PILOT_ACTIVATION_EVIDENCE_MISSING",)}
    reasons: list[str] = []
    if evidence.get("evidence_version") != EVIDENCE_VERSION:
        reasons.append("PILOT_ACTIVATION_EVIDENCE_VERSION_INVALID")
    if evidence.get("activation_contract_version") != CONTRACT_VERSION:
        reasons.append("PILOT_ACTIVATION_CONTRACT_VERSION_INVALID")
    for field in ("tenant_reference", "environment_reference", "pilot_reference", "policy_reference", "policy_hash", "human_approval_reference", "readiness_decision_hash", "evidence_chain_reference", "activation_request_hash", "evidence_hash"):
        if not is_sha256_reference(evidence.get(field)):
            reasons.append(f"{field.upper()}_INVALID")
    expected = sha256_reference({key: value for key, value in evidence.items() if key != "evidence_hash"})
    if evidence.get("evidence_hash") != expected:
        reasons.append("PILOT_ACTIVATION_EVIDENCE_HASH_MISMATCH")
    return {"valid": not reasons, "reason_codes": tuple(sorted(set(reasons)))}


def compute_activation_request_hash(activation_request: Mapping[str, Any]) -> str:
    return sha256_reference({key: value for key, value in activation_request.items() if key != "activation_request_hash"})


def _evaluate_readiness_context(readiness_context: Mapping[str, Any] | None, timestamp: datetime) -> dict[str, Any]:
    if not isinstance(readiness_context, Mapping):
        return {"state": BLOCKED, "reason_codes": ("READINESS_CONTEXT_MISSING",), "evidence": {}}
    return evaluate_euria_customer_onboarding(
        readiness_context.get("contract") if isinstance(readiness_context.get("contract"), Mapping) else None,
        human_approval=readiness_context.get("human_approval") if isinstance(readiness_context.get("human_approval"), Mapping) else None,
        policy_validation=readiness_context.get("policy_validation") if isinstance(readiness_context.get("policy_validation"), Mapping) else None,
        onboarding_controls=readiness_context.get("onboarding_controls") if isinstance(readiness_context.get("onboarding_controls"), Mapping) else None,
        now=timestamp,
    )


def _validate_activation_request(value: Mapping[str, Any] | None, now: datetime, used_nonce_references: tuple[str, ...] | list[str] | set[str]) -> list[str]:
    if not isinstance(value, Mapping):
        return ["ACTIVATION_REQUEST_MALFORMED"]
    reasons: list[str] = []
    for field in REQUIRED_REQUEST_FIELDS:
        if value.get(field) in ("", None):
            reasons.append(f"{field.upper()}_MISSING")
    if value.get("contract_version") != CONTRACT_VERSION:
        reasons.append("ACTIVATION_CONTRACT_VERSION_INVALID")
    for field in HASH_REFERENCE_FIELDS:
        if not is_sha256_reference(value.get(field)):
            reasons.append(f"{field.upper()}_INVALID")
    if value.get("activation_request_hash") and value.get("activation_request_hash") != compute_activation_request_hash(value):
        reasons.append("ACTIVATION_REQUEST_HASH_MISMATCH")
    issued = _parse_timestamp(value.get("timestamp"))
    expires = _parse_timestamp(value.get("expires_at"))
    if issued is None:
        reasons.append("ACTIVATION_TIMESTAMP_INVALID")
    if expires is None:
        reasons.append("ACTIVATION_EXPIRES_AT_INVALID")
    elif expires <= now:
        reasons.append("ACTIVATION_EXPIRED")
    if issued is not None and expires is not None and expires <= issued:
        reasons.append("ACTIVATION_TIMESTAMP_ORDER_INVALID")
    if value.get("revoked") is True:
        reasons.append("ACTIVATION_REVOKED")
    if value.get("state") not in (None, ACTIVATION_REQUESTED, ACTIVATION_VALIDATING):
        reasons.append("ACTIVATION_STATE_INVALID")
    if value.get("nonce_reference") in set(used_nonce_references):
        reasons.append("ACTIVATION_NONCE_REPLAY_DETECTED")
    return reasons


def _validate_readiness_binding(
    activation_request: Mapping[str, Any] | None,
    readiness_result: Mapping[str, Any],
    readiness_context: Mapping[str, Any] | None,
) -> list[str]:
    if not isinstance(activation_request, Mapping):
        return []
    reasons: list[str] = []
    if readiness_result.get("state") != PILOT_READY:
        reasons.append("PILOT_READY_REQUIRED")
    if readiness_result.get("execution_authorized") is not False:
        reasons.append("READINESS_EXECUTION_AUTHORITY_VIOLATION")
    evidence = readiness_result.get("evidence") if isinstance(readiness_result.get("evidence"), Mapping) else None
    verification = verify_onboarding_bridge_evidence(evidence)
    if verification.get("valid") is not True:
        reasons.extend(f"READINESS_EVIDENCE_{reason}" for reason in verification.get("reason_codes", ()))
    readiness_hash = evidence.get("evidence_hash") if isinstance(evidence, Mapping) else None
    if activation_request.get("readiness_decision_hash") != readiness_hash:
        reasons.append("READINESS_DECISION_HASH_MISMATCH")
    bindings = {
        "tenant_reference": "tenant_reference",
        "environment_reference": "environment_reference",
        "policy_reference": "policy_reference",
        "human_approval_reference": "approval_reference",
    }
    if isinstance(evidence, Mapping):
        for request_field, evidence_field in bindings.items():
            if activation_request.get(request_field) != evidence.get(evidence_field):
                reasons.append(f"READINESS_{request_field.upper()}_MISMATCH")
    context_reasons = _validate_activation_against_current_context(activation_request, readiness_context)
    reasons.extend(context_reasons)
    return reasons


def _validate_activation_against_current_context(activation_request: Mapping[str, Any], readiness_context: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(readiness_context, Mapping):
        return ["READINESS_CONTEXT_MISSING"]
    controls = readiness_context.get("onboarding_controls")
    policy = readiness_context.get("policy_validation")
    if not isinstance(controls, Mapping) or not isinstance(policy, Mapping):
        return ["READINESS_CONTEXT_MALFORMED"]
    device = controls.get("device_identity")
    verifier = controls.get("verifier_enrollment")
    attestation = controls.get("attestation")
    challenge = controls.get("challenge")
    evidence = controls.get("evidence")
    reasons: list[str] = []
    expected = {
        "policy_hash": policy.get("observed_policy_hash"),
        "identity_reference": _mapping_value(device, "device_reference"),
        "identity_hash": _mapping_value(device, "identity_hash"),
        "device_reference": _mapping_value(device, "device_reference"),
        "device_hash": _mapping_value(device, "identity_hash"),
        "verifier_reference": _mapping_value(verifier, "verifier_reference"),
        "verifier_hash": _mapping_value(verifier, "verifier_hash"),
        "attestation_reference": _mapping_value(attestation, "attestation_reference"),
        "attestation_hash": _mapping_value(attestation, "attestation_reference"),
        "nonce_reference": _mapping_value(challenge, "nonce_reference"),
        "challenge_reference": _mapping_value(challenge, "challenge_reference"),
        "evidence_chain_reference": _mapping_value(evidence, "evidence_chain_hash"),
    }
    for field, expected_value in expected.items():
        if activation_request.get(field) != expected_value:
            reasons.append(f"ACTIVATION_{field.upper()}_CURRENT_STATE_MISMATCH")
    return reasons


def _validate_gateway_authorization(
    activation_request: Mapping[str, Any] | None,
    readiness_result: Mapping[str, Any],
    gateway_authorization: Mapping[str, Any] | None,
) -> list[str]:
    if not isinstance(gateway_authorization, Mapping):
        return ["GATEWAY_AUTHORIZATION_MISSING"]
    reasons: list[str] = []
    if gateway_authorization.get("gateway_authoritative") is not True:
        reasons.append("GATEWAY_AUTHORITY_MISSING")
    if gateway_authorization.get("decision") != EXECUTION_AUTHORIZED:
        reasons.append("GATEWAY_DECISION_NOT_AUTHORIZED")
    if gateway_authorization.get("execution_authorized") is not True:
        reasons.append("GATEWAY_EXECUTION_AUTHORIZATION_MISSING")
    if gateway_authorization.get("revoked") is True:
        reasons.append("GATEWAY_AUTHORIZATION_REVOKED")
    if gateway_authorization.get("indeterminate") is True or gateway_authorization.get("unavailable") is True:
        reasons.append("GATEWAY_AUTHORIZATION_INDETERMINATE")
    for field in ("gateway_decision_hash", "activation_request_hash", "readiness_decision_hash", "policy_hash", "tenant_reference", "environment_reference"):
        if not is_sha256_reference(gateway_authorization.get(field)):
            reasons.append(f"GATEWAY_{field.upper()}_INVALID")
    if isinstance(activation_request, Mapping):
        for field in ("activation_request_hash", "readiness_decision_hash", "policy_hash", "tenant_reference", "environment_reference"):
            if gateway_authorization.get(field) != activation_request.get(field):
                reasons.append(f"GATEWAY_{field.upper()}_MISMATCH")
    if readiness_result.get("state") != PILOT_READY:
        reasons.append("GATEWAY_READINESS_NOT_CURRENT")
    return reasons


def _validate_non_authority_metadata(value: Any) -> list[str]:
    reasons: list[str] = []
    forbidden_truths = {
        "EURIA_EXECUTION_AUTHORITY": "EURIA_EXECUTION_AUTHORITY_FORBIDDEN",
        "EURIA_POLICY_AUTHORITY": "EURIA_POLICY_AUTHORITY_FORBIDDEN",
        "EURIA_APPROVAL_AUTHORITY": "EURIA_APPROVAL_AUTHORITY_FORBIDDEN",
        "EURIA_DEPLOYMENT_AUTHORITY": "EURIA_DEPLOYMENT_AUTHORITY_FORBIDDEN",
        "pilot_readiness_execution_authority": "PILOT_READINESS_EXECUTION_AUTHORITY_FORBIDDEN",
        "execution_authorized": "EXECUTION_AUTHORIZATION_FORBIDDEN",
        "enforcement_gateway_bypass": "ENFORCEMENT_GATEWAY_BYPASS_FORBIDDEN",
        "deployment_authorized": "DEPLOYMENT_AUTHORIZATION_FORBIDDEN",
        "production_activation": "PRODUCTION_ACTIVATION_FORBIDDEN",
    }
    for field, reason in forbidden_truths.items():
        if _contains_truthy_key(value, field):
            reasons.append(reason)
    return reasons


def _terminal_blocked_state(activation_request: Mapping[str, Any] | None, now: datetime) -> str:
    if isinstance(activation_request, Mapping):
        if activation_request.get("revoked") is True:
            return REVOKED
        expires = _parse_timestamp(activation_request.get("expires_at"))
        if expires is not None and expires <= now:
            return EXPIRED
    return BLOCKED


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


def _mapping_value(value: Any, field: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(field)
    return None


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
