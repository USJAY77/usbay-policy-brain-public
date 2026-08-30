from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.customer_onboarding_contracts import build_customer_onboarding_record
from governance.euria_customer_onboarding import evaluate_euria_customer_onboarding
from governance.euria_enterprise_intake import build_euria_enterprise_intake_contract, compute_contract_hash
from governance.euria_pilot_activation_gateway_readiness import (
    BLOCKED,
    EXECUTION_AUTHORIZED,
    build_pilot_activation_request,
    compute_activation_request_hash,
    evaluate_pilot_activation_gateway_readiness,
    verify_pilot_activation_evidence,
)
from governance.hashing import sha256_reference


pytestmark = pytest.mark.governance

NOW = datetime(2026, 8, 8, 10, 0, 0, tzinfo=timezone.utc)
CREATED = "2026-08-08T09:00:00Z"
EXPIRES = "2026-08-09T09:00:00Z"
EXPIRED = "2026-08-07T09:00:00Z"

TENANT = "sha256:" + ("1" * 64)
ENVIRONMENT = "sha256:" + ("2" * 64)
POLICY = "sha256:" + ("3" * 64)
APPROVAL = "sha256:" + ("4" * 64)
CONSENT = "sha256:" + ("5" * 64)
DEVICE = "sha256:" + ("6" * 64)
VERIFIER = "sha256:" + ("7" * 64)
ATTESTATION = "sha256:" + ("8" * 64)
PILOT = "sha256:" + ("9" * 64)
POLICY_HASH = "sha256:" + ("a" * 64)


def _contract(**overrides: object) -> dict:
    contract = build_euria_enterprise_intake_contract(
        request_id="euria-activation-1",
        created_at=CREATED,
        expires_at=EXPIRES,
        tenant_reference=TENANT,
        environment_reference=ENVIRONMENT,
        requested_capability="enterprise-pilot",
        requested_action="request-pilot-activation",
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
        "request_id": "euria-activation-1",
        "tenant_reference": TENANT,
        "environment_reference": ENVIRONMENT,
        "policy_reference": POLICY,
        "human_approval_reference": APPROVAL,
        "approval_reference": APPROVAL,
        "device_reference": DEVICE,
        "approval_hash": "sha256:" + ("b" * 64),
        "approved": True,
        "ai_generated_only": False,
        "generated_by": "HUMAN",
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
        "expected_policy_hash": POLICY_HASH,
        "observed_policy_hash": POLICY_HASH,
        "registry_reference": "sha256:" + ("c" * 64),
        "expected_registry_hash": "sha256:" + ("d" * 64),
        "observed_registry_hash": "sha256:" + ("d" * 64),
    }
    policy.update(overrides)
    return policy


def _record(**overrides: object) -> dict:
    payload = {
        "onboarding_id": "onboard-euria-activation-1",
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
            "policy_reference": POLICY,
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
        "intake_evidence_hash": "sha256:" + ("e" * 64),
        "onboarding_evidence_hash": "sha256:" + ("f" * 64),
        "device_evidence_hash": "sha256:" + ("0" * 64),
        "verifier_evidence_hash": "sha256:" + ("1" * 64),
        "attestation_evidence_hash": "sha256:" + ("2" * 64),
        "policy_decision_evidence_hash": "sha256:" + ("3" * 64),
        "approval_evidence_hash": "sha256:" + ("4" * 64),
        "registry_evidence_hash": "sha256:" + ("5" * 64),
        "evidence_chain_hash": "sha256:" + ("6" * 64),
        "previous_evidence_hash": "sha256:" + ("7" * 64),
        "current_evidence_hash": "sha256:" + ("8" * 64),
        "expected_evidence_chain_hash": "sha256:" + ("9" * 64),
        "observed_evidence_chain_hash": "sha256:" + ("9" * 64),
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


def _readiness_context(**overrides: object) -> dict:
    context = {"contract": _contract(), "human_approval": _approval(), "policy_validation": _policy(), "onboarding_controls": _controls()}
    context.update(overrides)
    return context


def _readiness_hash(context: dict | None = None) -> str:
    result = evaluate_euria_customer_onboarding(**(context or _readiness_context()), now=NOW)
    return result["evidence"]["evidence_hash"]


def _activation_request(**overrides: object) -> dict:
    request = build_pilot_activation_request(
        request_id="euria-activation-1",
        tenant_reference=TENANT,
        environment_reference=ENVIRONMENT,
        pilot_reference=PILOT,
        onboarding_reference="sha256:" + ("e" * 64),
        policy_reference=POLICY,
        policy_hash=POLICY_HASH,
        human_approval_reference=APPROVAL,
        identity_reference=DEVICE,
        identity_hash="sha256:" + ("a" * 64),
        device_reference=DEVICE,
        device_hash="sha256:" + ("a" * 64),
        verifier_reference=VERIFIER,
        verifier_hash="sha256:" + ("b" * 64),
        attestation_reference=ATTESTATION,
        attestation_hash=ATTESTATION,
        readiness_decision_hash=_readiness_hash(),
        evidence_chain_reference="sha256:" + ("6" * 64),
        timestamp=CREATED,
        expires_at=EXPIRES,
        nonce_reference="sha256:" + ("d" * 64),
        challenge_reference="sha256:" + ("c" * 64),
    )
    request.update(overrides)
    request["activation_request_hash"] = compute_activation_request_hash(request)
    return request


def _gateway(request: dict | None = None, **overrides: object) -> dict:
    activation = request or _activation_request()
    gateway = {
        "gateway_authoritative": True,
        "decision": EXECUTION_AUTHORIZED,
        "execution_authorized": True,
        "gateway_decision_hash": "sha256:" + ("f" * 64),
        "activation_request_hash": activation["activation_request_hash"],
        "readiness_decision_hash": activation["readiness_decision_hash"],
        "policy_hash": activation["policy_hash"],
        "tenant_reference": activation["tenant_reference"],
        "environment_reference": activation["environment_reference"],
    }
    gateway.update(overrides)
    return gateway


def _evaluate(request: dict | None = None, context: dict | None = None, gateway: dict | None = None, **kwargs: object) -> dict:
    activation = request or _activation_request()
    return evaluate_pilot_activation_gateway_readiness(
        activation,
        readiness_context=context or _readiness_context(),
        gateway_authorization=gateway if gateway is not None else _gateway(activation),
        now=NOW,
        **kwargs,
    )


@pytest.mark.parametrize(
    ("request_override", "context_override", "gateway_override"),
    (
        ({"execution_authorized": True}, {}, {}),
        ({"state": "PILOT_READY"}, {}, {}),
        ({}, {}, {"execution_authorized": False}),
        ({}, {"human_approval": None}, {}),
        ({}, {"human_approval": _approval(expires_at=EXPIRED)}, {}),
        ({}, {"human_approval": _approval(revoked=True)}, {}),
        ({}, {"policy_validation": _policy(observed_policy_hash="sha256:" + ("b" * 64))}, {}),
        ({"policy_hash": "sha256:" + ("b" * 64)}, {}, {}),
        ({"tenant_reference": "sha256:" + ("b" * 64)}, {}, {}),
        ({"environment_reference": "sha256:" + ("b" * 64)}, {}, {}),
        ({}, {"onboarding_controls": _controls(pilot={**_controls()["pilot"], "revoked": True})}, {}),
        ({"expires_at": EXPIRED}, {}, {}),
        ({"identity_hash": "sha256:" + ("b" * 64)}, {}, {}),
        ({"device_reference": "sha256:" + ("b" * 64)}, {}, {}),
        ({}, {"onboarding_controls": _controls(verifier_enrollment={**_controls()["verifier_enrollment"], "enrolled": False})}, {}),
        ({"verifier_reference": "sha256:" + ("b" * 64)}, {}, {}),
        ({}, {"onboarding_controls": _controls(attestation={**_controls()["attestation"], "result": "FAIL"})}, {}),
        ({}, {"onboarding_controls": _controls(challenge={**_controls()["challenge"], "expires_at": EXPIRED})}, {}),
        ({}, {"onboarding_controls": _controls(challenge={**_controls()["challenge"], "nonce_replayed": True})}, {}),
        ({}, {"onboarding_controls": _controls(evidence=_evidence(observed_evidence_chain_hash="sha256:" + ("8" * 64)))}, {}),
        ({}, {"onboarding_controls": _controls(evidence=None)}, {}),
        (None, {}, {}),
        ({"state": "UNKNOWN"}, {}, {}),
        ({}, {"onboarding_controls": _controls(customer_onboarding_record={**_record(), "euria_requested_state": "PILOT_READY"})}, {}),
        ({"readiness_decision_hash": "sha256:" + ("b" * 64)}, {}, {}),
        ({"EURIA_EXECUTION_AUTHORITY": True}, {}, {}),
        ({"EURIA_APPROVAL_AUTHORITY": True}, {}, {}),
        ({"EURIA_POLICY_AUTHORITY": True}, {}, {}),
        ({"EURIA_DEPLOYMENT_AUTHORITY": True}, {}, {}),
        ({}, {}, {"unavailable": True}),
    ),
)
def test_activation_negative_matrix_blocks(request_override: dict | None, context_override: dict, gateway_override: dict) -> None:
    context = _readiness_context(**context_override)
    request = None if request_override is None else _activation_request(**request_override)
    gateway = _gateway(request or _activation_request(), **gateway_override)

    result = evaluate_pilot_activation_gateway_readiness(
        request,
        readiness_context=context,
        gateway_authorization=gateway,
        now=NOW,
    )

    assert result["state"] != EXECUTION_AUTHORIZED
    assert result["execution_authorized"] is False


def test_replayed_activation_nonce_blocks() -> None:
    request = _activation_request()
    result = _evaluate(request=request, used_nonce_references=(request["nonce_reference"],))

    assert result["state"] == BLOCKED
    assert "ACTIVATION_NONCE_REPLAY_DETECTED" in result["reason_codes"]


def test_positive_path_requires_gateway_authority_and_emits_verifiable_evidence() -> None:
    request = _activation_request()
    result = _evaluate(request=request)

    assert result["state"] == EXECUTION_AUTHORIZED
    assert result["execution_authorized"] is True
    assert result["gateway_authorized"] is True
    assert result["gateway_final_authority"] is True
    assert result["euria_execution_authority"] is False
    assert result["euria_policy_authority"] is False
    assert result["euria_approval_authority"] is False
    assert result["euria_deployment_authority"] is False
    assert result["pilot_readiness_execution_authority"] is False
    assert result["provider_execution"] is False
    assert result["production_activation"] is False
    assert verify_pilot_activation_evidence(result["evidence"]) == {"valid": True, "reason_codes": ()}


def test_pilot_ready_without_gateway_authorization_blocks() -> None:
    result = evaluate_pilot_activation_gateway_readiness(_activation_request(), readiness_context=_readiness_context(), now=NOW)

    assert result["state"] == BLOCKED
    assert "GATEWAY_AUTHORIZATION_MISSING" in result["reason_codes"]


def test_sensitive_activation_metadata_blocks_without_leaking_evidence() -> None:
    result = _evaluate(request=_activation_request(raw_payload=("pass" + "word=blocked")))

    assert result["state"] == BLOCKED
    assert "SENSITIVE_DATA_FORBIDDEN" in result["reason_codes"]
    assert "password" not in " ".join(str(value).lower() for value in result["evidence"].values())
