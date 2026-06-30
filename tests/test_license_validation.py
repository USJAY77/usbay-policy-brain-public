from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.license_contracts import build_license_record
from governance.license_registry import LicenseRegistry
from governance.license_validation import empty_license_dashboard_state, evaluate_license_governance


pytestmark = pytest.mark.governance


def license_record(**overrides):
    payload = {
        "license_id": "lic-1",
        "customer_id": "customer-1",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "license_tier": "ENTERPRISE",
        "license_state": "ACTIVE",
        "entitlements": ["GOVERNANCE_MODULE_POLICY", "AUDIT_EXPORT"],
        "policy_version": "policy-v1",
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "issued_at": "2026-06-18T00:00:00Z",
        "expires_at": "2027-06-18T00:00:00Z",
        "reason_codes": [],
        "fail_closed": False,
    }
    payload.update(overrides)
    return build_license_record(**payload)


def test_license_governance_active_when_controls_pass():
    record = license_record()
    result = evaluate_license_governance(
        record=record,
        entitlement_context={"tenant_id": "tenant-1", "workspace_id": "ws-1", "requested_capability": "AUDIT_EXPORT"},
        registry=LicenseRegistry([record]),
        now=datetime(2026, 6, 18, tzinfo=timezone.utc),
    )

    assert result["license_status"] == "ACTIVE"
    assert result["license_tier"] == "ENTERPRISE"
    assert result["license_entitlement_status"] == "VALID"
    assert result["active_license_count"] == 1
    assert result["payment_processing_enabled"] is False


def test_license_governance_blocks_missing_license():
    result = evaluate_license_governance(record=None)

    assert result["license_status"] == "BLOCKED"
    assert result["license_tier"] == "UNKNOWN"
    assert "MISSING_LICENSE" in result["license_reason_codes"]


def test_license_governance_blocks_unlicensed_audit_export():
    record = license_record(entitlements=[])
    result = evaluate_license_governance(
        record=record,
        entitlement_context={"requested_capability": "AUDIT_EXPORT"},
        registry=LicenseRegistry([record]),
    )

    assert result["license_status"] == "BLOCKED"
    assert "AUDIT_EXPORT_NOT_LICENSED" in result["license_reason_codes"]


def test_empty_license_dashboard_state_is_fail_closed():
    state = empty_license_dashboard_state()

    assert state["license_status"] == "BLOCKED"
    assert state["license_tier"] == "UNKNOWN"
    assert state["license_reason_codes"] == ["MISSING_LICENSE"]
    assert state["billing_execution_enabled"] is False
    assert state["auto_renewal"] is False
    assert state["auto_upgrade"] is False
    assert state["auto_assignment"] is False
