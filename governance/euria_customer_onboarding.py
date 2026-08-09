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
INTAKE_VALIDATED = "INTAKE_VALIDATED"
REVIEW_REQUIRED_STATE = "REVIEW_REQUIRED"
HUMAN_APPROVAL_PENDING = "HUMAN_APPROVAL_PENDING"
HUMAN_APPROVED = "HUMAN_APPROVED"
POLICY_VALIDATION_PENDING = "POLICY_VALIDATION_PENDING"
POLICY_VALIDATED = "POLICY_VALIDATED"
ONBOARDING_PENDING = "ONBOARDING_PENDING"
IDENTITY_PENDING = "IDENTITY_PENDING"
VERIFIER_PENDING = "VERIFIER_PENDING"
ATTESTATION_PENDING = "ATTESTATION_PENDING"
PILOT_READY = "PILOT_READY"
BLOCKED = "BLOCKED"
REVOKED = "REVOKED"
EXPIRED = "EXPIRED"

ALLOWED_STATES = frozenset(
    {
        INTAKE_RECEIVED,
        INTAKE_VALIDATED,
        REVIEW_REQUIRED_STATE,
        HUMAN_APPROVAL_PENDING,
        HUMAN_APPROVED,
        POLICY_VALIDATION_PENDING,
        POLICY_VALIDATED,
        ONBOARDING_PENDING,
        IDENTITY_PENDING,
        VERIFIER_PENDING,
        ATTESTATION_PENDING,
        PILOT_READY,
        BLOCKED,
        REVOKED,
        EXPIRED,
    }
)

REQUIRED_EVIDENCE_FIELDS = (
    "intake_evidence_hash",
    "onboarding_evidence_hash",
    "device_evidence_hash",
    "verifier_evidence_hash",
    "attestation_evidence_hash",
    "policy_decision_evidence_hash",
    "approval_evidence_hash",
    "registry_evidence_hash",
    "evidence_chain_hash",
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
        if human_approval is None:
            state = REVIEW_REQUIRED_STATE
        else:
            approval_reasons = _validate_human_approval_contract(contract, human_approval, timestamp, onboarding_controls)
            if approval_reasons:
                reasons.extend(approval_reasons)
                state = BLOCKED
            else:
                state = POLICY_VALIDATION_PENDING if policy_validation is None else REVIEW_REQUIRED_STATE
    elif intake_state != APPROVED_FOR_PILOT:
        reasons.append(f"EURIA_INTAKE_STATE_BLOCKED:{intake_state}")
        state = _blocked_state_from_intake(intake_state)
    else:
        approval_reasons = _validate_human_approval_contract(contract, human_approval, timestamp, onboarding_controls)
        if approval_reasons:
            reasons.extend(approval_reasons)
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
    record_reasons = _validate_onboarding_record_binding(onboarding_record, contract, timestamp)
    if record_reasons:
        reasons.extend(record_reasons)
        return _decision(contract, BLOCKED, reasons, timestamp, intake_result)
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
        "policy_hash": "",
        "registry_reference": "",
        "approval_reference": _safe_value(contract, "human_approval_reference"),
        "previous_evidence_hash": "",
        "state": state if state in ALLOWED_STATES else BLOCKED,
        "reason_codes": sorted(str(reason) for reason in reasons if reason),
        "timestamp": issued_at,
        "contract_hash": compute_contract_hash(contract) if isinstance(contract, Mapping) else sha256_reference({"missing": True}),
        "evidence_hash": "",
    }
    evidence["evidence_hash"] = sha256_reference({key: value for key, value in evidence.items() if key != "evidence_hash"})
    return evidence


def verify_onboarding_bridge_evidence(evidence: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(evidence, Mapping):
        return {"valid": False, "reason_codes": ("ONBOARDING_BRIDGE_EVIDENCE_MISSING",)}
    reasons: list[str] = []
    if evidence.get("contract_version") != CONTRACT_VERSION:
        reasons.append("ONBOARDING_BRIDGE_EVIDENCE_VERSION_INVALID")
    if evidence.get("state") not in ALLOWED_STATES:
        reasons.append("ONBOARDING_BRIDGE_EVIDENCE_STATE_INVALID")
    for field in ("contract_hash", "evidence_hash"):
        if not is_sha256_reference(evidence.get(field)):
            reasons.append(f"ONBOARDING_BRIDGE_{field.upper()}_INVALID")
    if not isinstance(evidence.get("reason_codes"), list):
        reasons.append("ONBOARDING_BRIDGE_REASON_CODES_MALFORMED")
    expected_hash = sha256_reference({key: value for key, value in evidence.items() if key != "evidence_hash"})
    if evidence.get("evidence_hash") != expected_hash:
        reasons.append("ONBOARDING_BRIDGE_EVIDENCE_HASH_MISMATCH")
    return {"valid": not reasons, "reason_codes": tuple(sorted(set(reasons)))}


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
    if not is_sha256_reference(expected_hash) or not is_sha256_reference(observed_hash):
        reasons.append("POLICY_HASH_REFERENCE_INVALID")
    elif expected_hash != observed_hash:
        reasons.append("POLICY_HASH_MISMATCH")
    registry_reference = policy_validation.get("registry_reference")
    expected_registry_hash = policy_validation.get("expected_registry_hash")
    observed_registry_hash = policy_validation.get("observed_registry_hash")
    if not is_sha256_reference(registry_reference):
        reasons.append("POLICY_REGISTRY_REFERENCE_INVALID")
    if not is_sha256_reference(expected_registry_hash) or not is_sha256_reference(observed_registry_hash):
        reasons.append("POLICY_REGISTRY_HASH_INVALID")
    elif expected_registry_hash != observed_registry_hash:
        reasons.append("POLICY_REGISTRY_MISMATCH")
    if policy_validation.get("execution_authorized") is True:
        reasons.append("POLICY_EXECUTION_AUTHORITY_BLOCKED")
    if policy_validation.get("policy_mutation") is True:
        reasons.append("POLICY_MUTATION_FORBIDDEN")
    return reasons


def _validate_human_approval_contract(
    contract: Mapping[str, Any] | None,
    approval: Mapping[str, Any] | None,
    now: datetime,
    onboarding_controls: Mapping[str, Any] | None,
) -> list[str]:
    if not isinstance(contract, Mapping):
        return ["HUMAN_APPROVAL_CONTRACT_MALFORMED"]
    if not isinstance(approval, Mapping):
        return ["HUMAN_APPROVAL_MISSING"]
    reasons: list[str] = []
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
    if approval.get("approved") is not True:
        reasons.append("HUMAN_APPROVAL_NOT_APPROVED")
    if approval.get("revoked") is True:
        reasons.append("HUMAN_APPROVAL_REVOKED")
    if approval.get("ai_generated_only") is not False:
        reasons.append("AI_GENERATED_APPROVAL_BLOCKED")
    if approval.get("generated_by") in {"EURIA", "AUTONOMOUS_AGENT", "AI_AGENT"}:
        reasons.append("SYNTHETIC_APPROVAL_BLOCKED")
    if approval.get("source_system") == "EURIA":
        reasons.append("EURIA_APPROVAL_AUTHORITY_BLOCKED")
    if approval.get("replayed") is True or approval.get("nonce_replayed") is True:
        reasons.append("HUMAN_APPROVAL_REPLAY_DETECTED")
    approval_reference = approval.get("approval_reference", approval.get("human_approval_reference"))
    if not is_sha256_reference(approval_reference):
        reasons.append("HUMAN_APPROVAL_REFERENCE_INVALID")
    if approval.get("approval_hash") is not None and not is_sha256_reference(approval.get("approval_hash")):
        reasons.append("HUMAN_APPROVAL_HASH_INVALID")
    device = _mapping_value(onboarding_controls, "device_identity")
    device_reference = _mapping_value(device, "device_reference")
    if approval.get("device_reference") is not None and approval.get("device_reference") != device_reference:
        reasons.append("HUMAN_APPROVAL_DEVICE_MISMATCH")
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


def _validate_onboarding_record_binding(record: Any, contract: Mapping[str, Any] | None, now: datetime) -> list[str]:
    if not isinstance(record, Mapping):
        return ["CUSTOMER_ONBOARDING_RECORD_MALFORMED"]
    reasons: list[str] = []
    if record.get("tenant_id") != _safe_value(contract, "tenant_reference"):
        reasons.append("CUSTOMER_ONBOARDING_TENANT_MISMATCH")
    if record.get("workspace_id") != _safe_value(contract, "environment_reference"):
        reasons.append("CUSTOMER_ONBOARDING_ENVIRONMENT_MISMATCH")
    if record.get("policy_reference") not in (None, _safe_value(contract, "policy_reference")):
        reasons.append("CUSTOMER_ONBOARDING_POLICY_MISMATCH")
    if record.get("requested_state") == PILOT_READY or record.get("euria_requested_state") == PILOT_READY:
        reasons.append("EURIA_PILOT_READY_ASSERTION_FORBIDDEN")
    if record.get("revoked") is True:
        reasons.append("CUSTOMER_ONBOARDING_REVOKED")
    expires_at = record.get("expires_at")
    if expires_at is not None:
        parsed = _parse_timestamp(expires_at)
        if parsed is None:
            reasons.append("CUSTOMER_ONBOARDING_EXPIRES_AT_INVALID")
        elif parsed <= now:
            reasons.append("CUSTOMER_ONBOARDING_EXPIRED")
    if record.get("onboarding_state") not in {"ACTIVE", "APPROVED"}:
        reasons.append("CUSTOMER_ONBOARDING_STATE_NOT_READY")
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
    previous_hash = evidence.get("previous_evidence_hash")
    current_hash = evidence.get("current_evidence_hash")
    expected_chain_hash = evidence.get("expected_evidence_chain_hash")
    observed_chain_hash = evidence.get("observed_evidence_chain_hash")
    if previous_hash is not None and not is_sha256_reference(previous_hash):
        reasons.append("PREVIOUS_EVIDENCE_HASH_INVALID")
    if current_hash is not None and not is_sha256_reference(current_hash):
        reasons.append("CURRENT_EVIDENCE_HASH_INVALID")
    if expected_chain_hash is not None or observed_chain_hash is not None:
        if not is_sha256_reference(expected_chain_hash) or not is_sha256_reference(observed_chain_hash):
            reasons.append("EVIDENCE_CHAIN_HASH_INVALID")
        elif expected_chain_hash != observed_chain_hash:
            reasons.append("EVIDENCE_CHAIN_INTEGRITY_FAILURE")
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


def _blocked_state_from_intake(intake_state: str) -> str:
    if intake_state == REVOKED:
        return REVOKED
    if intake_state == EXPIRED:
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
