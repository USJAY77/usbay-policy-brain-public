from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.customer_onboarding_contracts import build_customer_onboarding_record
from governance.euria_customer_onboarding import (
    ATTESTATION_PENDING,
    BLOCKED,
    IDENTITY_PENDING,
    ONBOARDING_PENDING,
    PILOT_READY,
    POLICY_VALIDATION_PENDING,
    REVIEW_REQUIRED_STATE,
    VERIFIER_PENDING,
    evaluate_euria_customer_onboarding,
    generate_onboarding_bridge_evidence,
    verify_onboarding_bridge_evidence,
)
from governance.euria_enterprise_intake import build_euria_enterprise_intake_contract, compute_contract_hash
from governance.hashing import sha256_reference


pytestmark = pytest.mark.governance

NOW = datetime(2026, 8, 7, 10, 0, 0, tzinfo=timezone.utc)
CREATED = "2026-08-07T09:00:00Z"
EXPIRES = "2026-08-08T09:00:00Z"
EXPIRED = "2026-08-06T09:00:00Z"

TENANT = "sha256:" + ("1" * 64)
ENVIRONMENT = "sha256:" + ("2" * 64)
POLICY = "sha256:" + ("3" * 64)
APPROVAL = "sha256:" + ("4" * 64)
CONSENT = "sha256:" + ("5" * 64)
DEVICE = "sha256:" + ("6" * 64)
VERIFIER = "sha256:" + ("7" * 64)
ATTESTATION = "sha256:" + ("8" * 64)
PILOT = "sha256:" + ("9" * 64)


def _contract(**overrides: object) -> dict:
    contract = build_euria_enterprise_intake_contract(
        request_id="euria-onboarding-1",
        created_at=CREATED,
        expires_at=EXPIRES,
        tenant_reference=TENANT,
        environment_reference=ENVIRONMENT,
        requested_capability="enterprise-pilot",
        requested_action="request-pilot-onboarding",
        risk_classification="enterprise",
        policy_reference=POLICY,
        human_approval_reference=APPROVAL,
        customer_consent_reference=CONSENT,
        data_classification="minimum_governance_metadata",
    )
    contract.update(overrides)
    contract["contract_hash"] = compute_contract_hash(contract)
    return contract


def _approval(**overrides: object) -> dict:
    approval = {
        "request_id": "euria-onboarding-1",
        "tenant_reference": TENANT,
        "environment_reference": ENVIRONMENT,
        "policy_reference": POLICY,
        "human_approval_reference": APPROVAL,
        "approved": True,
        "ai_generated_only": False,
        "revoked": False,
        "issued_at": CREATED,
        "expires_at": EXPIRES,
    }
    approval.update(overrides)
    return approval


def _policy(**overrides: object) -> dict:
    policy = {
        "policy_brain_authoritative": True,
        "policy_reference": POLICY,
        "decision": "ALLOW",
        "execution_authorized": False,
        "expected_policy_hash": "sha256:" + ("a" * 64),
        "observed_policy_hash": "sha256:" + ("a" * 64),
        "registry_reference": "sha256:" + ("b" * 64),
        "expected_registry_hash": "sha256:" + ("c" * 64),
        "observed_registry_hash": "sha256:" + ("c" * 64),
    }
    policy.update(overrides)
    return policy


def _record(**overrides: object) -> dict:
    payload = {
        "onboarding_id": "onboard-euria-1",
        "tenant_id": TENANT,
        "workspace_id": ENVIRONMENT,
        "policy_version": "policy-v1",
        "audit_linkage": "audit-linkage",
        "evidence_linkage": "evidence-linkage",
        "customer_classification": "ENTERPRISE",
        "jurisdiction": "EU",
        "risk_classification": "HIGH",
        "workspace_owner": "owner-reference",
        "onboarding_state": "ACTIVE",
        "human_approval": True,
        "created_at": CREATED,
        "governance_terms_accepted": True,
        "reason_codes": [],
        "fail_closed": False,
    }
    payload.update(overrides)
    record = build_customer_onboarding_record(**payload)
    record.update(
        {
            "document_library_status": "READY",
            "policy_registry_status": "READY",
            "audit_registry_status": "READY",
            "release_governance_status": "READY",
            "tenant_boundary_status": "READY",
        }
    )
    return record


def _evidence(**overrides: object) -> dict:
    evidence = {
        "intake_evidence_hash": "sha256:" + ("b" * 64),
        "onboarding_evidence_hash": "sha256:" + ("c" * 64),
        "device_evidence_hash": "sha256:" + ("d" * 64),
        "verifier_evidence_hash": "sha256:" + ("e" * 64),
        "attestation_evidence_hash": "sha256:" + ("f" * 64),
        "policy_decision_evidence_hash": "sha256:" + ("0" * 64),
        "approval_evidence_hash": "sha256:" + ("1" * 64),
        "registry_evidence_hash": "sha256:" + ("2" * 64),
        "evidence_chain_hash": "sha256:" + ("3" * 64),
        "previous_evidence_hash": "sha256:" + ("4" * 64),
        "current_evidence_hash": "sha256:" + ("5" * 64),
        "expected_evidence_chain_hash": "sha256:" + ("6" * 64),
        "observed_evidence_chain_hash": "sha256:" + ("6" * 64),
    }
    evidence.update(overrides)
    evidence["evidence_bundle_hash"] = sha256_reference(evidence)
    return evidence


def _controls(**overrides: object) -> dict:
    controls = {
        "customer_onboarding_record": _record(),
        "device_identity": {
            "device_reference": DEVICE,
            "identity_hash": "sha256:" + ("a" * 64),
            "tenant_reference": TENANT,
            "environment_reference": ENVIRONMENT,
            "enrolled": True,
            "revoked": False,
        },
        "verifier_enrollment": {
            "verifier_reference": VERIFIER,
            "verifier_hash": "sha256:" + ("b" * 64),
            "tenant_reference": TENANT,
            "environment_reference": ENVIRONMENT,
            "enrolled": True,
            "revoked": False,
        },
        "challenge": {
            "challenge_reference": "sha256:" + ("c" * 64),
            "nonce_reference": "sha256:" + ("d" * 64),
            "issued_at": CREATED,
            "expires_at": EXPIRES,
            "replayed": False,
            "nonce_replayed": False,
        },
        "attestation": {
            "attestation_reference": ATTESTATION,
            "device_reference": DEVICE,
            "verifier_reference": VERIFIER,
            "result": "PASS",
            "revoked": False,
        },
        "pilot": {
            "pilot_reference": PILOT,
            "tenant_reference": TENANT,
            "environment_reference": ENVIRONMENT,
            "policy_reference": POLICY,
            "onboarding_ready": True,
            "revoked": False,
        },
        "evidence": _evidence(),
    }
    controls.update(overrides)
    return controls


def _evaluate(**overrides: object) -> dict:
    contract = overrides.pop("contract", _contract())
    approval = overrides.pop("human_approval", _approval())
    policy = overrides.pop("policy_validation", _policy())
    controls = overrides.pop("onboarding_controls", _controls())
    return evaluate_euria_customer_onboarding(
        contract,  # type: ignore[arg-type]
        human_approval=approval,  # type: ignore[arg-type]
        policy_validation=policy,  # type: ignore[arg-type]
        onboarding_controls=controls,  # type: ignore[arg-type]
        now=NOW,
    )


def test_valid_intake_without_human_approval_cannot_become_pilot_ready() -> None:
    result = evaluate_euria_customer_onboarding(_contract(), now=NOW)

    assert result["state"] == REVIEW_REQUIRED_STATE
    assert result["onboarding_ready"] is False


def test_valid_human_approval_alone_does_not_yield_pilot_ready() -> None:
    result = evaluate_euria_customer_onboarding(_contract(), human_approval=_approval(), now=NOW)

    assert result["state"] == POLICY_VALIDATION_PENDING
    assert result["onboarding_ready"] is False
    assert result["execution_authorized"] is False


def test_valid_approval_and_policy_without_attestation_does_not_yield_pilot_ready() -> None:
    result = _evaluate(onboarding_controls=_controls(attestation=None))

    assert result["state"] == ATTESTATION_PENDING
    assert result["onboarding_ready"] is False


@pytest.mark.parametrize(
    "approval_override",
    (
        {"approved": False},
        {"ai_generated_only": True},
        {"generated_by": "EURIA"},
        {"generated_by": "AUTONOMOUS_AGENT"},
        {"source_system": "EURIA"},
        {"replayed": True},
        {"request_id": "wrong-request"},
        {"expires_at": EXPIRED},
        {"revoked": True},
        {"tenant_reference": "sha256:" + ("a" * 64)},
        {"environment_reference": "sha256:" + ("b" * 64)},
        {"policy_reference": "sha256:" + ("c" * 64)},
    ),
)
def test_invalid_approval_or_binding_blocks(approval_override: dict[str, object]) -> None:
    result = _evaluate(human_approval=_approval(**approval_override))

    assert result["state"] == BLOCKED
    assert result["onboarding_ready"] is False


def test_policy_hash_mismatch_blocks() -> None:
    result = _evaluate(policy_validation=_policy(observed_policy_hash="sha256:" + ("b" * 64)))

    assert result["state"] == BLOCKED
    assert "POLICY_HASH_MISMATCH" in result["reason_codes"]


def test_policy_reference_missing_blocks() -> None:
    result = _evaluate(policy_validation=_policy(policy_reference=""))

    assert result["state"] == BLOCKED
    assert "EURIA_INTAKE_POLICY_VALIDATION_REFERENCE_MISMATCH" in result["reason_codes"]


def test_registry_mismatch_blocks() -> None:
    result = _evaluate(policy_validation=_policy(observed_registry_hash="sha256:" + ("d" * 64)))

    assert result["state"] == BLOCKED
    assert "POLICY_REGISTRY_MISMATCH" in result["reason_codes"]


def test_missing_customer_onboarding_record_is_pending() -> None:
    result = _evaluate(onboarding_controls=_controls(customer_onboarding_record=None))

    assert result["state"] == ONBOARDING_PENDING
    assert result["execution_authorized"] is False


def test_missing_device_enrollment_is_identity_pending() -> None:
    result = _evaluate(onboarding_controls=_controls(device_identity=None))

    assert result["state"] == IDENTITY_PENDING


def test_wrong_device_binding_blocks() -> None:
    result = _evaluate(onboarding_controls=_controls(device_identity={**_controls()["device_identity"], "tenant_reference": "sha256:" + ("a" * 64)}))

    assert result["state"] == BLOCKED
    assert "DEVICE_IDENTITY_TENANT_MISMATCH" in result["reason_codes"]


def test_missing_verifier_enrollment_is_verifier_pending() -> None:
    result = _evaluate(onboarding_controls=_controls(verifier_enrollment=None))

    assert result["state"] == VERIFIER_PENDING


def test_expired_challenge_blocks() -> None:
    result = _evaluate(onboarding_controls=_controls(challenge={**_controls()["challenge"], "expires_at": EXPIRED}))

    assert result["state"] == BLOCKED
    assert "CHALLENGE_EXPIRED" in result["reason_codes"]


def test_replayed_challenge_blocks() -> None:
    result = _evaluate(onboarding_controls=_controls(challenge={**_controls()["challenge"], "replayed": True}))

    assert result["state"] == BLOCKED
    assert "CHALLENGE_REPLAY_DETECTED" in result["reason_codes"]


def test_missing_attestation_is_pending() -> None:
    result = _evaluate(onboarding_controls=_controls(attestation=None))

    assert result["state"] == ATTESTATION_PENDING


def test_invalid_attestation_blocks() -> None:
    result = _evaluate(onboarding_controls=_controls(attestation={**_controls()["attestation"], "result": "FAIL"}))

    assert result["state"] == BLOCKED
    assert "ATTESTATION_INVALID" in result["reason_codes"]


def test_revoked_pilot_blocks() -> None:
    result = _evaluate(onboarding_controls=_controls(pilot={**_controls()["pilot"], "revoked": True}))

    assert result["state"] == BLOCKED
    assert "PILOT_REVOKED" in result["reason_codes"]


def test_revoked_customer_state_blocks() -> None:
    record = _record()
    record["revoked"] = True
    result = _evaluate(onboarding_controls=_controls(customer_onboarding_record=record))

    assert result["state"] == BLOCKED
    assert "CUSTOMER_ONBOARDING_REVOKED" in result["reason_codes"]


def test_expired_onboarding_state_blocks() -> None:
    record = _record()
    record["expires_at"] = EXPIRED
    result = _evaluate(onboarding_controls=_controls(customer_onboarding_record=record))

    assert result["state"] == BLOCKED
    assert "CUSTOMER_ONBOARDING_EXPIRED" in result["reason_codes"]


def test_contradictory_metadata_blocks() -> None:
    record = _record()
    record["policy_reference"] = "sha256:" + ("a" * 64)
    result = _evaluate(onboarding_controls=_controls(customer_onboarding_record=record))

    assert result["state"] == BLOCKED
    assert "CUSTOMER_ONBOARDING_POLICY_MISMATCH" in result["reason_codes"]


def test_malformed_intake_fails_closed() -> None:
    result = _evaluate(contract=["malformed"])

    assert result["state"] == BLOCKED
    assert result["execution_authorized"] is False


def test_unknown_state_fails_closed_in_evidence() -> None:
    evidence = generate_onboarding_bridge_evidence(_contract(), "UNKNOWN", [], NOW)

    assert evidence["state"] == BLOCKED


def test_unknown_customer_onboarding_state_fails_closed() -> None:
    result = _evaluate(onboarding_controls=_controls(customer_onboarding_record=_record(onboarding_state="UNKNOWN")))

    assert result["state"] == BLOCKED


@pytest.mark.parametrize(
    ("field", "reason"),
    (
        ("EURIA_EXECUTION_AUTHORITY", "EURIA_EXECUTION_AUTHORITY_FORBIDDEN"),
        ("EURIA_POLICY_AUTHORITY", "EURIA_POLICY_AUTHORITY_FORBIDDEN"),
        ("EURIA_APPROVAL_AUTHORITY", "EURIA_APPROVAL_AUTHORITY_FORBIDDEN"),
        ("EURIA_DEPLOYMENT_AUTHORITY", "EURIA_DEPLOYMENT_AUTHORITY_FORBIDDEN"),
    ),
)
def test_euria_authorities_cannot_be_asserted(field: str, reason: str) -> None:
    result = _evaluate(onboarding_controls=_controls(**{field: True}))

    assert result["state"] == BLOCKED
    assert reason in result["reason_codes"]


def test_onboarding_readiness_cannot_bypass_enforcement_gateway() -> None:
    result = _evaluate(onboarding_controls=_controls(enforcement_gateway_bypass=True))

    assert result["state"] == BLOCKED
    assert result["execution_authorized"] is False
    assert result["enforcement_gateway_required"] is True


def test_evidence_tampering_detected() -> None:
    evidence = _evidence()
    evidence["device_evidence_hash"] = "sha256:" + ("1" * 64)
    result = _evaluate(onboarding_controls=_controls(evidence=evidence))

    assert result["state"] == BLOCKED
    assert "ONBOARDING_EVIDENCE_TAMPERED" in result["reason_codes"]


def test_evidence_chain_integrity_failure_blocks() -> None:
    result = _evaluate(onboarding_controls=_controls(evidence=_evidence(observed_evidence_chain_hash="sha256:" + ("7" * 64))))

    assert result["state"] == BLOCKED
    assert "EVIDENCE_CHAIN_INTEGRITY_FAILURE" in result["reason_codes"]


def test_euria_cannot_set_pilot_ready_directly() -> None:
    record = _record()
    record["euria_requested_state"] = PILOT_READY
    result = _evaluate(onboarding_controls=_controls(customer_onboarding_record=record))

    assert result["state"] == BLOCKED
    assert "EURIA_PILOT_READY_ASSERTION_FORBIDDEN" in result["reason_codes"]


def test_missing_mandatory_evidence_reference_blocks() -> None:
    result = _evaluate(onboarding_controls=_controls(evidence=_evidence(approval_evidence_hash="")))

    assert result["state"] == BLOCKED
    assert "APPROVAL_EVIDENCE_HASH_INVALID" in result["reason_codes"]


def test_sensitive_data_leakage_blocks_and_evidence_is_hash_only() -> None:
    result = _evaluate(onboarding_controls=_controls(raw_payload=("pass" + "word=not-allowed")))

    assert result["state"] == BLOCKED
    assert "SENSITIVE_DATA_FORBIDDEN" in result["reason_codes"]
    serialized_evidence = " ".join(str(value).lower() for value in result["evidence"].values())
    assert "password" not in serialized_evidence
    assert "raw_payload" not in serialized_evidence


def test_valid_fully_governed_onboarding_reaches_pilot_ready_only_after_all_controls_pass() -> None:
    result = _evaluate()

    assert result["state"] == PILOT_READY
    assert result["onboarding_ready"] is True
    assert result["execution_authorized"] is False
    assert result["deployment_authorized"] is False
    assert result["provider_execution"] is False
    assert result["production_activation"] is False
    assert result["euria_execution_authority"] is False
    assert result["euria_policy_authority"] is False
    assert result["euria_approval_authority"] is False
    assert result["euria_deployment_authority"] is False


def test_evidence_generated_deterministically_and_verifies() -> None:
    first = _evaluate()["evidence"]
    second = _evaluate()["evidence"]

    assert first == second
    assert verify_onboarding_bridge_evidence(first) == {"valid": True, "reason_codes": ()}


def test_tampered_bridge_evidence_verification_fails() -> None:
    evidence = dict(_evaluate()["evidence"])
    evidence["state"] = BLOCKED

    result = verify_onboarding_bridge_evidence(evidence)

    assert result["valid"] is False
    assert "ONBOARDING_BRIDGE_EVIDENCE_HASH_MISMATCH" in result["reason_codes"]
