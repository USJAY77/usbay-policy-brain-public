from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.euria_enterprise_intake import (
    APPROVED_FOR_PILOT,
    BLOCKED,
    ELIGIBLE_FOR_GATEWAY,
    EXPIRED,
    REVIEW_REQUIRED,
    REVOKED,
    build_euria_enterprise_intake_contract,
    compute_contract_hash,
    evaluate_euria_enterprise_intake,
    generate_euria_intake_evidence,
    normalize_policy_brain_request,
)


NOW = datetime(2026, 8, 7, 10, 0, 0, tzinfo=timezone.utc)
CREATED = "2026-08-07T09:00:00Z"
EXPIRES = "2026-08-08T09:00:00Z"
EXPIRED_AT = "2026-08-06T09:00:00Z"

TENANT = "sha256:" + ("1" * 64)
ENVIRONMENT = "sha256:" + ("2" * 64)
POLICY = "sha256:" + ("3" * 64)
APPROVAL = "sha256:" + ("4" * 64)
CONSENT = "sha256:" + ("5" * 64)


def _contract() -> dict:
    return build_euria_enterprise_intake_contract(
        request_id="euria-intake-1",
        created_at=CREATED,
        expires_at=EXPIRES,
        tenant_reference=TENANT,
        environment_reference=ENVIRONMENT,
        requested_capability="enterprise-pilot",
        requested_action="request-pilot-evaluation",
        risk_classification="enterprise",
        policy_reference=POLICY,
        human_approval_reference=APPROVAL,
        customer_consent_reference=CONSENT,
        data_classification="minimum_governance_metadata",
    )


def _approval(**overrides: object) -> dict:
    approval = {
        "request_id": "euria-intake-1",
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
    }
    policy.update(overrides)
    return policy


def test_valid_intake_without_approval_requires_review() -> None:
    result = evaluate_euria_enterprise_intake(_contract(), now=NOW)

    assert result["state"] == REVIEW_REQUIRED
    assert result["execution_eligibility"] == REVIEW_REQUIRED
    assert result["euria_execution_authority"] is False
    assert result["euria_policy_authority"] is False
    assert result["euria_approval_authority"] is False
    assert result["euria_deployment_authority"] is False


def test_valid_human_approval_and_policy_validation_approve_for_pilot_only() -> None:
    result = evaluate_euria_enterprise_intake(_contract(), human_approval=_approval(), policy_validation=_policy(), now=NOW)

    assert result["state"] == APPROVED_FOR_PILOT
    assert result["execution_eligibility"] == ELIGIBLE_FOR_GATEWAY
    assert result["policy_brain_request"]["policy_brain_authoritative"] is True
    assert result["policy_brain_request"]["euria_policy_authority"] is False


def test_normalized_policy_brain_request_preserves_authority_boundary() -> None:
    request = normalize_policy_brain_request(_contract())

    assert request["source_system"] == "EURIA"
    assert request["policy_reference"] == POLICY
    assert request["policy_brain_authoritative"] is True
    assert request["euria_policy_authority"] is False


@pytest.mark.parametrize(
    "field",
    ("request_id", "tenant_reference", "environment_reference", "policy_reference"),
)
def test_missing_required_fields_block(field: str) -> None:
    contract = _contract()
    del contract[field]

    result = evaluate_euria_enterprise_intake(contract, now=NOW)

    assert result["state"] == BLOCKED
    assert result["execution_eligibility"] == BLOCKED


def test_missing_human_approval_cannot_approve_for_pilot() -> None:
    result = evaluate_euria_enterprise_intake(_contract(), policy_validation=_policy(), now=NOW)

    assert result["state"] == REVIEW_REQUIRED
    assert result["state"] != APPROVED_FOR_PILOT


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("expires_at", EXPIRED_AT),
        ("tenant_reference", "sha256:" + ("9" * 64)),
        ("environment_reference", "sha256:" + ("9" * 64)),
        ("policy_reference", "sha256:" + ("9" * 64)),
        ("ai_generated_only", True),
        ("revoked", True),
    ),
)
def test_invalid_approval_blocks(field: str, value: object) -> None:
    result = evaluate_euria_enterprise_intake(
        _contract(),
        human_approval=_approval(**{field: value}),
        policy_validation=_policy(),
        now=NOW,
    )

    assert result["state"] == BLOCKED
    assert result["execution_eligibility"] == BLOCKED


def test_expired_intake_contract_returns_expired_without_eligibility() -> None:
    contract = _contract()
    contract["expires_at"] = EXPIRED_AT
    contract["contract_hash"] = compute_contract_hash(contract)

    result = evaluate_euria_enterprise_intake(contract, now=NOW)

    assert result["state"] == EXPIRED
    assert result["execution_eligibility"] == BLOCKED


def test_revoked_intake_returns_revoked_without_eligibility() -> None:
    contract = _contract()
    contract["revoked"] = True
    contract["contract_hash"] = compute_contract_hash(contract)

    result = evaluate_euria_enterprise_intake(contract, now=NOW)

    assert result["state"] == REVOKED
    assert result["execution_eligibility"] == BLOCKED


def test_unknown_source_system_blocks() -> None:
    contract = _contract()
    contract["source_system"] = "OTHER"
    contract["contract_hash"] = compute_contract_hash(contract)

    result = evaluate_euria_enterprise_intake(contract, now=NOW)

    assert result["state"] == BLOCKED


@pytest.mark.parametrize(
    "field",
    (
        "EURIA_EXECUTION_AUTHORITY",
        "EURIA_POLICY_AUTHORITY",
        "EURIA_APPROVAL_AUTHORITY",
        "EURIA_DEPLOYMENT_AUTHORITY",
    ),
)
def test_euria_authority_override_blocks(field: str) -> None:
    contract = _contract()
    contract[field] = True
    contract["contract_hash"] = compute_contract_hash(contract)

    result = evaluate_euria_enterprise_intake(contract, now=NOW)

    assert result["state"] == BLOCKED
    assert result["execution_eligibility"] == BLOCKED


def test_malformed_contract_blocks() -> None:
    result = evaluate_euria_enterprise_intake(["not", "a", "contract"], now=NOW)  # type: ignore[arg-type]

    assert result["state"] == BLOCKED
    assert result["execution_eligibility"] == BLOCKED


def test_tampered_contract_hash_blocks() -> None:
    contract = _contract()
    contract["contract_hash"] = "sha256:" + ("9" * 64)

    result = evaluate_euria_enterprise_intake(contract, now=NOW)

    assert result["state"] == BLOCKED


def test_missing_evidence_reference_blocks() -> None:
    contract = _contract()
    contract["customer_consent_reference"] = ""
    contract["contract_hash"] = compute_contract_hash(contract)

    result = evaluate_euria_enterprise_intake(contract, now=NOW)

    assert result["state"] == BLOCKED


def test_policy_validation_must_be_policy_brain_authoritative() -> None:
    result = evaluate_euria_enterprise_intake(
        _contract(),
        human_approval=_approval(),
        policy_validation=_policy(policy_brain_authoritative=False),
        now=NOW,
    )

    assert result["state"] == BLOCKED
    assert result["execution_eligibility"] == BLOCKED


def test_evidence_is_hash_only_and_deterministic() -> None:
    contract = _contract()
    first = generate_euria_intake_evidence(contract, REVIEW_REQUIRED, NOW)
    second = generate_euria_intake_evidence(contract, REVIEW_REQUIRED, NOW)

    assert first == second
    assert first["contract_hash"].startswith("sha256:")
    assert first["decision_hash"].startswith("sha256:")
    assert "customer" not in " ".join(str(value).lower() for value in first.values())


def test_sensitive_customer_data_blocks() -> None:
    contract = _contract()
    contract["raw_customer_data"] = "password=should-not-be-here"

    result = evaluate_euria_enterprise_intake(contract, now=NOW)

    assert result["state"] == BLOCKED
    assert result["execution_eligibility"] == BLOCKED
