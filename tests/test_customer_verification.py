from __future__ import annotations

import pytest

from governance.customer_verification import evaluate_customer_verification


pytestmark = pytest.mark.governance


def verification(**overrides):
    payload = {
        "tenant_id": "tenant-1",
        "jurisdiction": "EU",
        "risk_classification": "MEDIUM",
        "workspace_owner": "owner-1",
    }
    payload.update(overrides)
    return payload


def test_valid_customer_verification():
    result = evaluate_customer_verification(verification(), known_tenant_ids=set(), assigned_jurisdiction="EU")

    assert result["customer_verification_status"] == "VERIFIED"
    assert result["tenant_creation_enabled"] is False


def test_duplicate_tenant_identity_blocks():
    result = evaluate_customer_verification(verification(), known_tenant_ids={"tenant-1"}, assigned_jurisdiction="EU")

    assert "DUPLICATE_TENANT_IDENTITY" in result["reason_codes"]


def test_conflicting_jurisdiction_blocks():
    result = evaluate_customer_verification(verification(jurisdiction="US"), assigned_jurisdiction="EU")

    assert "CONFLICTING_JURISDICTION" in result["reason_codes"]


def test_missing_risk_and_owner_block():
    result = evaluate_customer_verification(verification(risk_classification="", workspace_owner=""))

    assert "MISSING_RISK_CLASSIFICATION" in result["reason_codes"]
    assert "MISSING_WORKSPACE_OWNER" in result["reason_codes"]
