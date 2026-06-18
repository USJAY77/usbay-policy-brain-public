from __future__ import annotations

import pytest

from governance.api_access_control import evaluate_api_access_control
from governance.api_security_contracts import build_api_security_record


pytestmark = pytest.mark.governance


def api_record(**overrides):
    payload = {
        "api_id": "api-1",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "license_entitlement": True,
        "classification": "CUSTOMER",
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


def test_api_access_control_valid_for_owner():
    result = evaluate_api_access_control(api_record(), requesting_tenant_id="tenant-1", requesting_workspace_id="ws-1")

    assert result["api_access_control_status"] == "VALID"
    assert result["auto_approval"] is False


def test_api_access_control_blocks_cross_tenant_and_missing_policy():
    result = evaluate_api_access_control(
        api_record(access_control_policy=False),
        requesting_tenant_id="tenant-2",
        requesting_workspace_id="ws-2",
    )

    assert "CROSS_TENANT_API_ACCESS" in result["reason_codes"]
    assert "MISSING_ACCESS_CONTROL" in result["reason_codes"]
