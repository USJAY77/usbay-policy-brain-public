from __future__ import annotations

import pytest

from governance.api_security_contracts import build_api_security_record
from governance.api_security_registry import ApiSecurityRegistry, empty_api_security_dashboard_state, evaluate_api_security_governance


pytestmark = pytest.mark.governance


def api_record(**overrides):
    payload = {
        "api_id": "api-1",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "license_entitlement": True,
        "classification": "INTERNAL",
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


def test_api_security_registry_read_only_summary():
    registry = ApiSecurityRegistry([api_record()])

    assert registry.summary()["api_security_registry_status"] == "VALID"
    assert registry.summary()["api_invocation_enabled"] is False
    assert registry.get_api("api-1")["api_id"] == "api-1"


def test_api_security_governance_valid_when_all_controls_pass():
    record = api_record()
    result = evaluate_api_security_governance(
        record=record,
        registry=ApiSecurityRegistry([record]),
        requesting_tenant_id="tenant-1",
        requesting_workspace_id="ws-1",
    )

    assert result["api_security_status"] == "GOVERNED"
    assert result["network_access_enabled"] is False
    assert result["auto_remediation"] is False


def test_api_security_governance_blocks_cross_tenant_and_missing_entitlement():
    result = evaluate_api_security_governance(
        record=api_record(license_entitlement=False),
        requesting_tenant_id="tenant-2",
    )

    assert result["api_security_status"] == "BLOCKED"
    assert "CROSS_TENANT_API_ACCESS" in result["api_reason_codes"]
    assert "GOVERNANCE_BYPASS_ATTEMPT" in result["api_reason_codes"]


def test_empty_api_security_dashboard_state_is_fail_closed():
    state = empty_api_security_dashboard_state()

    assert state["api_security_status"] == "BLOCKED"
    assert state["api_reason_codes"] == ["UNKNOWN_API"]
    assert state["api_invocation_enabled"] is False
    assert state["auto_approval"] is False
