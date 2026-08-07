from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from governance.customer_onboarding import evaluate_customer_onboarding
from governance.euria_enterprise_intake import (
    APPROVED_FOR_PILOT,
    EURIA_APPROVAL_AUTHORITY,
    EURIA_DEPLOYMENT_AUTHORITY,
    EURIA_EXECUTION_AUTHORITY,
    EURIA_POLICY_AUTHORITY,
    REVIEW_REQUIRED,
    compute_contract_hash,
    evaluate_euria_enterprise_intake,
)
from governance.hashing import is_sha256_reference, sha256_reference


CONTRACT_VERSION = "usbay.euria.customer_onboarding_bridge.v1"

INTAKE_RECEIVED = "INTAKE_RECEIVED"
REVIEW_REQUIRED_STATE = "REVIEW_REQUIRED"
HUMAN_APPROVED = "HUMAN_APPROVED"
POLICY_VALIDATED = "POLICY_VALIDATED"
ONBOARDING_PENDING = "ONBOARDING_PENDING"
IDENTITY_PENDING = "IDENTITY_PENDING"
VERIFIER_PENDING = "VERIFIER_PENDING"
ATTESTATION_PENDING = "ATTESTATION_PENDING"
PILOT_READY = "PILOT_READY"
BLOCKED = "BLOCKED"

ALLOWED_STATES = frozenset(
    {
        INTAKE_RECEIVED,
        REVIEW_REQUIRED_STATE,
        HUMAN_APPROVED,
        POLICY_VALIDATED,
        ONBOARDING_PENDING,
        IDENTITY_PENDING,
        VERIFIER_PENDING,
        ATTESTATION_PENDING,
        PILOT_READY,
        BLOCKED,
    }
)

REQUIRED_EVIDENCE_FIELDS = (
    "intake_evidence_hash",
    "onboarding_evidence_hash",
    "device_evidence_hash",
    "verifier_evidence_hash",
    "attestation_evidence_hash",
    "policy_decision_evidence_hash",
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


def evaluate_euria_customer_onboarding(
    contract: Mapping[str, Any] | None,
    *,
    human_approval: Mapping[str, Any] | None = None,
    policy_validation: Mapping[str, Any] | None = None,
    onboarding_controls: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    timestamp = _utc_now(now)
    reasons: list[str] = []
    state = INTAKE_RECEIVED

    intake_result = evaluate_euria_enterprise_intake(
        contract,
        human_approval=human_approval,
        policy_validation=policy_validation,
        now=timestamp,
    )
    intake_state = str(intake_result.get("state", BLOCKED))
    reasons.extend(f"EURIA_INTAKE_{reason}" for reason in intake_result.get("reason_codes", ()))

    if not _euria_authority_boundary_preserved(intake_result):
        reasons.append("EURIA_AUTHORITY_BOUNDARY_VIOLATED")
        state = BLOCKED
    elif intake_state == REVIEW_REQUIRED:
        state = REVIEW_REQUIRED_STATE
    elif intake_state != APPROVED_FOR_PILOT:
        reasons.append(f"EURIA_INTAKE_STATE_BLOCKED:{intake_state}")
        state = BLOCKED
    else:
        state = HUMAN_APPROVED

    if state not in {HUMAN_APPROVED, POLICY_VALIDATED}:
        return _decision(contract, state, reasons, timestamp, intake_result)

    policy_reasons = _validate_policy_binding(contract, policy_validation)
    if policy_reasons:
        reasons.extend(policy_reasons)
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result)
    state = POLICY_VALIDATED

    if not isinstance(onboarding_controls, Mapping):
        reasons.append("ONBOARDING_CONTROLS_MISSING")
        return _decision(contract, ONBOARDING_PENDING, reasons, timestamp, intake_result)
    if _contains_sensitive_marker(onboarding_controls):
        reasons.append("SENSITIVE_DATA_FORBIDDEN")
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result)
    authority_reasons = _validate_non_authority_controls(onboarding_controls)
    if authority_reasons:
        reasons.extend(authority_reasons)
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result)

    onboarding_record = onboarding_controls.get("customer_onboarding_record")
    if onboarding_record is None:
        reasons.append("CUSTOMER_ONBOARDING_RECORD_MISSING")
        return _decision(contract, ONBOARDING_PENDING, reasons, timestamp, intake_result)
    onboarding_result = evaluate_customer_onboarding(
        record=onboarding_record if isinstance(onboarding_record, dict) else None,
        known_tenant_ids=set(),
        assigned_jurisdiction=str(onboarding_record.get("jurisdiction", "")) if isinstance(onboarding_record, Mapping) else None,
        human_approval=dict(human_approval) if isinstance(human_approval, Mapping) else None,
    )
    if onboarding_result.get("fail_closed") is True:
        reasons.extend(f"CUSTOMER_ONBOARDING_{reason}" for reason in onboarding_result.get("customer_onboarding_reason_codes", ()))
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result, onboarding_result)

    device_reasons, device_pending = _validate_bound_reference(
        onboarding_controls.get("device_identity"),
        contract,
        reference_field="device_reference",
        hash_field="identity_hash",
        required_ready_field="enrolled",
        revoked_reason="DEVICE_IDENTITY_REVOKED",
        mismatch_prefix="DEVICE_IDENTITY",
    )
    if device_pending:
        reasons.extend(device_reasons)
        return _decision(contract, IDENTITY_PENDING, reasons, timestamp, intake_result, onboarding_result)
    if device_reasons:
        reasons.extend(device_reasons)
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result, onboarding_result)

    verifier_reasons, verifier_pending = _validate_bound_reference(
        onboarding_controls.get("verifier_enrollment"),
        contract,
        reference_field="verifier_reference",
        hash_field="verifier_hash",
        required_ready_field="enrolled",
        revoked_reason="VERIFIER_REVOKED",
        mismatch_prefix="VERIFIER",
    )
    if verifier_pending:
        reasons.extend(verifier_reasons)
        return _decision(contract, VERIFIER_PENDING, reasons, timestamp, intake_result, onboarding_result)
    if verifier_reasons:
        reasons.extend(verifier_reasons)
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result, onboarding_result)

    challenge_reasons = _validate_challenge(onboarding_controls.get("challenge"), timestamp)
    if challenge_reasons:
        reasons.extend(challenge_reasons)
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result, onboarding_result)

    attestation = onboarding_controls.get("attestation")
    if attestation is None:
        reasons.append("ATTESTATION_MISSING")
        return _decision(contract, ATTESTATION_PENDING, reasons, timestamp, intake_result, onboarding_result)
    attestation_reasons = _validate_attestation(
        attestation,
        onboarding_controls.get("device_identity"),
        onboarding_controls.get("verifier_enrollment"),
    )
    if attestation_reasons:
        reasons.extend(attestation_reasons)
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result, onboarding_result)

    pilot_reasons = _validate_pilot_status(onboarding_controls.get("pilot"), contract)
    if pilot_reasons:
        reasons.extend(pilot_reasons)
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result, onboarding_result)

    evidence_reasons = _validate_evidence(onboarding_controls.get("evidence"))
    if evidence_reasons:
        reasons.extend(evidence_reasons)
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result, onboarding_result)

    return _decision(contract, PILOT_READY, reasons, timestamp, intake_result, onboarding_result)


def generate_onboarding_bridge_evidence(
    contract: Mapping[str, Any] | None,
    state: str,
    reasons: list[str] | tuple[str, ...],
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    issued_at = _utc_now(timestamp).isoformat().replace("+00:00", "Z")
    evidence = {
        "contract_version": CONTRACT_VERSION,
        "request_id": _safe_value(contract, "request_id"),
        "tenant_reference": _safe_value(contract, "tenant_reference"),
        "environment_reference": _safe_value(contract, "environment_reference"),
        "policy_reference": _safe_value(contract, "policy_reference"),
        "state": state if state in ALLOWED_STATES else BLOCKED,
        "reason_codes": sorted(str(reason) for reason in reasons if reason),
        "timestamp": issued_at,
        "contract_hash": compute_contract_hash(contract) if isinstance(contract, Mapping) else sha256_reference({"missing": True}),
        "evidence_hash": "",
    }
    evidence["evidence_hash"] = sha256_reference({key: value for key, value in evidence.items() if key != "evidence_hash"})
    return evidence


def _decision(
    contract: Mapping[str, Any] | None,
    state: str,
    reasons: list[str],
    timestamp: datetime,
    intake_result: Mapping[str, Any],
    onboarding_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    safe_state = state if state in ALLOWED_STATES else BLOCKED
    unique_reasons = sorted(set(str(reason) for reason in reasons if reason))
    return {
        "contract_version": CONTRACT_VERSION,
        "request_id": _safe_value(contract, "request_id"),
        "state": safe_state,
        "onboarding_ready": safe_state == PILOT_READY,
        "execution_authorized": False,
        "deployment_authorized": False,
        "provider_execution": False,
        "production_activation": False,
        "enforcement_gateway_required": True,
        "onboarding_readiness_bypasses_gateway": False,
        "euria_execution_authority": EURIA_EXECUTION_AUTHORITY,
        "euria_policy_authority": EURIA_POLICY_AUTHORITY,
        "euria_approval_authority": EURIA_APPROVAL_AUTHORITY,
        "euria_deployment_authority": EURIA_DEPLOYMENT_AUTHORITY,
        "reason_codes": tuple(unique_reasons),
        "intake_state": str(intake_result.get("state", BLOCKED)),
        "customer_onboarding_status": str(onboarding_result.get("customer_onboarding_status", "")) if onboarding_result else "",
        "evidence": generate_onboarding_bridge_evidence(contract, safe_state, unique_reasons, timestamp),
    }


def _validate_policy_binding(contract: Mapping[str, Any] | None, policy_validation: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(contract, Mapping) or not isinstance(policy_validation, Mapping):
        return ["POLICY_VALIDATION_MALFORMED"]
    reasons: list[str] = []
    if policy_validation.get("policy_reference") != contract.get("policy_reference"):
        reasons.append("POLICY_REFERENCE_MISMATCH")
    expected_hash = policy_validation.get("expected_policy_hash")
    observed_hash = policy_validation.get("observed_policy_hash")
    if expected_hash is not None or observed_hash is not None:
        if not is_sha256_reference(expected_hash) or not is_sha256_reference(observed_hash):
            reasons.append("POLICY_HASH_REFERENCE_INVALID")
        elif expected_hash != observed_hash:
            reasons.append("POLICY_HASH_MISMATCH")
    if policy_validation.get("execution_authorized") is True:
        reasons.append("POLICY_EXECUTION_AUTHORITY_BLOCKED")
    return reasons


def _validate_bound_reference(
    value: Any,
    contract: Mapping[str, Any] | None,
    *,
    reference_field: str,
    hash_field: str,
    required_ready_field: str,
    revoked_reason: str,
    mismatch_prefix: str,
) -> tuple[list[str], bool]:
    if value is None:
        return [f"{mismatch_prefix}_MISSING"], True
    if not isinstance(value, Mapping):
        return [f"{mismatch_prefix}_MALFORMED"], False
    reasons: list[str] = []
    if value.get(required_ready_field) is not True:
        reasons.append(f"{mismatch_prefix}_NOT_ENROLLED")
    if value.get("revoked") is True:
        reasons.append(revoked_reason)
    if value.get("tenant_reference") != _safe_value(contract, "tenant_reference"):
        reasons.append(f"{mismatch_prefix}_TENANT_MISMATCH")
    if value.get("environment_reference") != _safe_value(contract, "environment_reference"):
        reasons.append(f"{mismatch_prefix}_ENVIRONMENT_MISMATCH")
    for field in (reference_field, hash_field):
        if not is_sha256_reference(value.get(field)):
            reasons.append(f"{mismatch_prefix}_{field.upper()}_INVALID")
    return reasons, False


def _validate_challenge(value: Any, now: datetime) -> list[str]:
    if not isinstance(value, Mapping):
        return ["CHALLENGE_MALFORMED"]
    reasons: list[str] = []
    for field in ("challenge_reference", "nonce_reference"):
        if not is_sha256_reference(value.get(field)):
            reasons.append(f"{field.upper()}_INVALID")
    issued_at = _parse_timestamp(value.get("issued_at"))
    expires_at = _parse_timestamp(value.get("expires_at"))
    if issued_at is None:
        reasons.append("CHALLENGE_ISSUED_AT_INVALID")
    if expires_at is None:
        reasons.append("CHALLENGE_EXPIRES_AT_INVALID")
    elif expires_at <= now:
        reasons.append("CHALLENGE_EXPIRED")
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        reasons.append("CHALLENGE_TIMESTAMP_ORDER_INVALID")
    if value.get("replayed") is True or value.get("nonce_replayed") is True:
        reasons.append("CHALLENGE_REPLAY_DETECTED")
    return reasons


def _validate_attestation(attestation: Any, device: Any, verifier: Any) -> list[str]:
    if not isinstance(attestation, Mapping):
        return ["ATTESTATION_MALFORMED"]
    reasons: list[str] = []
    if not is_sha256_reference(attestation.get("attestation_reference")):
        reasons.append("ATTESTATION_REFERENCE_INVALID")
    if attestation.get("device_reference") != _mapping_value(device, "device_reference"):
        reasons.append("ATTESTATION_DEVICE_BINDING_MISMATCH")
    if attestation.get("verifier_reference") != _mapping_value(verifier, "verifier_reference"):
        reasons.append("ATTESTATION_VERIFIER_BINDING_MISMATCH")
    if attestation.get("result") != "PASS":
        reasons.append("ATTESTATION_INVALID")
    if attestation.get("revoked") is True:
        reasons.append("ATTESTATION_REVOKED")
    return reasons


def _validate_pilot_status(pilot: Any, contract: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(pilot, Mapping):
        return ["PILOT_STATUS_MALFORMED"]
    reasons: list[str] = []
    if not is_sha256_reference(pilot.get("pilot_reference")):
        reasons.append("PILOT_REFERENCE_INVALID")
    if pilot.get("tenant_reference") != _safe_value(contract, "tenant_reference"):
        reasons.append("PILOT_TENANT_MISMATCH")
    if pilot.get("environment_reference") != _safe_value(contract, "environment_reference"):
        reasons.append("PILOT_ENVIRONMENT_MISMATCH")
    if pilot.get("policy_reference") != _safe_value(contract, "policy_reference"):
        reasons.append("PILOT_POLICY_MISMATCH")
    if pilot.get("revoked") is True:
        reasons.append("PILOT_REVOKED")
    if pilot.get("onboarding_ready") is not True:
        reasons.append("PILOT_ONBOARDING_READY_MISSING")
    return reasons


def _validate_evidence(evidence: Any) -> list[str]:
    if not isinstance(evidence, Mapping):
        return ["ONBOARDING_EVIDENCE_MALFORMED"]
    reasons: list[str] = []
    for field in REQUIRED_EVIDENCE_FIELDS:
        if not is_sha256_reference(evidence.get(field)):
            reasons.append(f"{field.upper()}_INVALID")
    claimed_hash = evidence.get("evidence_bundle_hash")
    if claimed_hash is not None:
        expected_hash = sha256_reference({key: value for key, value in evidence.items() if key != "evidence_bundle_hash"})
        if claimed_hash != expected_hash:
            reasons.append("ONBOARDING_EVIDENCE_TAMPERED")
    return reasons


def _validate_non_authority_controls(controls: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    forbidden_truths = {
        "EURIA_EXECUTION_AUTHORITY": "EURIA_EXECUTION_AUTHORITY_FORBIDDEN",
        "EURIA_POLICY_AUTHORITY": "EURIA_POLICY_AUTHORITY_FORBIDDEN",
        "EURIA_APPROVAL_AUTHORITY": "EURIA_APPROVAL_AUTHORITY_FORBIDDEN",
        "EURIA_DEPLOYMENT_AUTHORITY": "EURIA_DEPLOYMENT_AUTHORITY_FORBIDDEN",
        "execution_authorized": "EXECUTION_AUTHORIZATION_FORBIDDEN",
        "deployment_authorized": "DEPLOYMENT_AUTHORIZATION_FORBIDDEN",
        "provider_execution": "PROVIDER_EXECUTION_FORBIDDEN",
        "production_activation": "PRODUCTION_ACTIVATION_FORBIDDEN",
        "enforcement_gateway_bypass": "ENFORCEMENT_GATEWAY_BYPASS_FORBIDDEN",
    }
    for field, reason in forbidden_truths.items():
        if _contains_truthy_key(controls, field):
            reasons.append(reason)
    return reasons


def _euria_authority_boundary_preserved(intake_result: Mapping[str, Any]) -> bool:
    return (
        intake_result.get("euria_execution_authority") is False
        and intake_result.get("euria_policy_authority") is False
        and intake_result.get("euria_approval_authority") is False
        and intake_result.get("euria_deployment_authority") is False
    )


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


def _mapping_value(value: Any, field: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(field)
    return None


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
