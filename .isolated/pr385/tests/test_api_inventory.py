from __future__ import annotations

import pytest

from governance.api_inventory import evaluate_api_inventory
from governance.api_security_contracts import build_api_security_record


pytestmark = pytest.mark.governance


def api_record(**overrides):
    payload = {
        "api_id": "api-1",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "license_entitlement": True,
        "classification": "ADMIN",
        "inventory_record": True,
        "access_control_policy": True,
        "rate_limit_policy": True,
        "input_validation_policy": True,
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "lineage_hash": "l" * 64,
        "policy_version": "policy-v1",
    }
    payload.update(overrides)
    return build_api_security_record(**payload)


def test_api_inventory_valid_when_registered_and_classified():
    result = evaluate_api_inventory(api_record())

    assert result["api_inventory_status"] == "VALID"
    assert result["api_invocation_enabled"] is False


def test_api_inventory_blocks_missing_record_and_classification():
    result = evaluate_api_inventory(api_record(inventory_record=False, classification=""))

    assert result["api_inventory_status"] == "BLOCKED"
    assert "MISSING_API_INVENTORY" in result["reason_codes"]
    assert "MISSING_CLASSIFICATION" in result["reason_codes"]
