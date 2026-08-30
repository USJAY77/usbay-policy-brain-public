from __future__ import annotations

import pytest

from governance.customer_onboarding_contracts import (
    FAIL_CLOSED_REASON_CODES,
    build_customer_onboarding_record,
    validate_customer_onboarding,
)


pytestmark = pytest.mark.governance


def onboarding(**overrides):
    payload = {
        "onboarding_id": "onboard-1",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "policy_version": "policy-v1",
        "audit_linkage": "audit-1",
        "evidence_linkage": "evidence-1",
        "customer_classification": "ENTERPRISE",
        "jurisdiction": "EU",
        "risk_classification": "MEDIUM",
        "workspace_owner": "owner-1",
        "onboarding_state": "ACTIVE",
        "human_approval": True,
        "created_at": "2026-06-18T00:00:00Z",
        "governance_terms_accepted": True,
        "reason_codes": [],
        "fail_closed": False,
    }
    payload.update(overrides)
    return build_customer_onboarding_record(**payload)


def test_valid_customer_onboarding_contract():
    result = validate_customer_onboarding(onboarding())

    assert result.valid is True
    assert result.status == "ACTIVE"


def test_missing_required_identifiers_block():
    result = validate_customer_onboarding(onboarding(tenant_id="", workspace_id="", policy_version=""))

    assert "MISSING_TENANT_ID" in result.reason_codes
    assert "MISSING_WORKSPACE_ID" in result.reason_codes
    assert "MISSING_POLICY_VERSION" in result.reason_codes


def test_missing_audit_evidence_and_approval_block():
    result = validate_customer_onboarding(onboarding(audit_linkage="", evidence_linkage="", human_approval=False))

    assert "MISSING_AUDIT_LINKAGE" in result.reason_codes
    assert "MISSING_EVIDENCE_LINKAGE" in result.reason_codes
    assert "NO_HUMAN_APPROVAL" in result.reason_codes


def test_missing_classification_jurisdiction_risk_and_owner_block():
    result = validate_customer_onboarding(
        onboarding(customer_classification="", jurisdiction="", risk_classification="", workspace_owner="")
    )

    assert "MISSING_CUSTOMER_CLASSIFICATION" in result.reason_codes
    assert "MISSING_JURISDICTION" in result.reason_codes
    assert "MISSING_RISK_CLASSIFICATION" in result.reason_codes
    assert "MISSING_WORKSPACE_OWNER" in result.reason_codes


def test_terms_auto_actions_and_sensitive_logging_block():
    record = onboarding(governance_terms_accepted=False)
    record.update({"auto_onboarding": True, "auto_approval": True, "note": "secret token"})

    result = validate_customer_onboarding(record)

    assert "GOVERNANCE_TERMS_NOT_ACCEPTED" in result.reason_codes
    assert "AUTO_ONBOARDING_FORBIDDEN" in result.reason_codes
    assert "AUTO_APPROVAL_FORBIDDEN" in result.reason_codes
    assert "SENSITIVE_DATA_LOGGING_FORBIDDEN" in result.reason_codes


def test_fail_closed_reason_code_registry_contains_required_codes():
    assert "MISSING_TENANT_ID" in FAIL_CLOSED_REASON_CODES
    assert "MISSING_TENANT_BOUNDARY" in FAIL_CLOSED_REASON_CODES
