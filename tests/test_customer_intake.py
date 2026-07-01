from __future__ import annotations

import pytest

from governance.customer_intake import evaluate_customer_intake


pytestmark = pytest.mark.governance


def intake(**overrides):
    payload = {
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "customer_classification": "ENTERPRISE",
        "jurisdiction": "EU",
        "governance_terms_accepted": True,
    }
    payload.update(overrides)
    return payload


def test_valid_customer_intake():
    result = evaluate_customer_intake(intake())

    assert result["customer_intake_status"] == "INTAKE_RECEIVED"
    assert result["workspace_creation_enabled"] is False


def test_missing_tenant_and_workspace_block():
    result = evaluate_customer_intake(intake(tenant_id="", workspace_id=""))

    assert "MISSING_TENANT_ID" in result["reason_codes"]
    assert "MISSING_WORKSPACE_ID" in result["reason_codes"]


def test_missing_terms_and_classification_block():
    result = evaluate_customer_intake(intake(customer_classification="", governance_terms_accepted=False))

    assert "MISSING_CUSTOMER_CLASSIFICATION" in result["reason_codes"]
    assert "GOVERNANCE_TERMS_NOT_ACCEPTED" in result["reason_codes"]
