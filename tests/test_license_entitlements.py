from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.license_contracts import build_license_record
from governance.license_entitlements import evaluate_license_entitlements


pytestmark = pytest.mark.governance


def license_record(**overrides):
    payload = {
        "license_id": "lic-1",
        "customer_id": "customer-1",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "license_tier": "SOVEREIGN",
        "license_state": "ACTIVE",
        "entitlements": ["GOVERNANCE_MODULE_POLICY", "AUDIT_EXPORT", "SOVEREIGN_DEPLOYMENT"],
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


def test_valid_entitlement_path():
    result = evaluate_license_entitlements(
        license_record(),
        {
            "customer_id": "customer-1",
            "tenant_id": "tenant-1",
            "workspace_id": "ws-1",
            "requested_capability": "SOVEREIGN_DEPLOYMENT",
        },
        now=datetime(2026, 6, 18, tzinfo=timezone.utc),
    )

    assert result["license_entitlement_status"] == "VALID"
    assert result["deployment_enabled"] is False
    assert result["auto_assignment"] is False


def test_tenant_workspace_and_capability_mismatches_block():
    result = evaluate_license_entitlements(
        license_record(entitlements=[]),
        {"tenant_id": "tenant-2", "workspace_id": "ws-2", "requested_capability": "UNLICENSED_CAPABILITY"},
    )

    assert result["license_entitlement_status"] == "BLOCKED"
    assert "TENANT_MISMATCH" in result["reason_codes"]
    assert "WORKSPACE_MISMATCH" in result["reason_codes"]
    assert "CAPABILITY_NOT_LICENSED" in result["reason_codes"]


def test_sovereign_capability_requires_sovereign_license():
    result = evaluate_license_entitlements(
        license_record(license_tier="ENTERPRISE"),
        {"requested_capability": "SOVEREIGN_DEPLOYMENT"},
    )

    assert "SOVEREIGN_LICENSE_REQUIRED" in result["reason_codes"]


def test_missing_dependencies_block_entitlement():
    result = evaluate_license_entitlements(
        license_record(),
        {"active_policy_registry": False, "active_audit_registry": False, "active_document_library": False},
    )

    assert "GOVERNANCE_MODULE_NOT_LICENSED" in result["reason_codes"]
    assert "AUDIT_EXPORT_NOT_LICENSED" in result["reason_codes"]
