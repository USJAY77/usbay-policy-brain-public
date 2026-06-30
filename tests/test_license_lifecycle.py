from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.license_contracts import build_license_record
from governance.license_lifecycle import evaluate_license_lifecycle


pytestmark = pytest.mark.governance


def license_record(**overrides):
    payload = {
        "license_id": "lic-1",
        "customer_id": "customer-1",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "license_tier": "STARTER",
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


def test_lifecycle_active_for_valid_license():
    result = evaluate_license_lifecycle(license_record(), now=datetime(2026, 6, 18, tzinfo=timezone.utc))

    assert result["license_status"] == "ACTIVE"
    assert result["license_expiry_status"] == "ACTIVE"
    assert result["auto_renewal"] is False


def test_lifecycle_blocks_expired_license():
    result = evaluate_license_lifecycle(
        license_record(expires_at="2026-01-01T00:00:00Z"),
        now=datetime(2026, 6, 18, tzinfo=timezone.utc),
    )

    assert result["license_status"] == "BLOCKED"
    assert result["license_expiry_status"] == "EXPIRED"
    assert "EXPIRED_LICENSE" in result["reason_codes"]


def test_lifecycle_blocks_unknown_tier():
    result = evaluate_license_lifecycle(license_record(license_tier="UNKNOWN"))

    assert result["license_tier"] == "UNKNOWN"
    assert "UNKNOWN_LICENSE_TIER" in result["reason_codes"]
