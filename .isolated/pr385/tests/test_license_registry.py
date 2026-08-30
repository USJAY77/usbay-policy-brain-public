from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.license_contracts import build_license_record
from governance.license_registry import LicenseRegistry, evaluate_license_registry


pytestmark = pytest.mark.governance


def license_record(**overrides):
    payload = {
        "license_id": "lic-1",
        "customer_id": "customer-1",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "license_tier": "ENTERPRISE",
        "license_state": "ACTIVE",
        "entitlements": ["GOVERNANCE_MODULE_POLICY"],
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


def test_license_registry_lists_copies_and_counts_active():
    record = license_record()
    registry = LicenseRegistry([record], now=datetime(2026, 6, 18, tzinfo=timezone.utc))

    listed = registry.list_licenses()
    listed[0]["license_state"] = "REVOKED"

    assert registry.get_license("lic-1")["license_state"] == "ACTIVE"
    assert registry.summary()["active_license_count"] == 1
    assert registry.summary()["license_registry_status"] == "VALID"


def test_empty_registry_blocks_read_only():
    summary = evaluate_license_registry(None)

    assert summary["license_registry_status"] == "BLOCKED"
    assert summary["license_reason_codes"] == ["MISSING_LICENSE"]
    assert summary["register_enabled"] is False
    assert summary["billing_execution_enabled"] is False


def test_registry_blocks_invalid_record():
    summary = LicenseRegistry([license_record(license_tier="UNKNOWN")]).summary()

    assert summary["license_registry_status"] == "BLOCKED"
    assert "UNKNOWN_LICENSE_TIER" in summary["license_reason_codes"]
