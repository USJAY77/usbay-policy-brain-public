from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.license_contracts import FAIL_CLOSED_REASON_CODES, build_license_record, validate_license_record


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


def test_valid_license_contract():
    result = validate_license_record(license_record(), now=datetime(2026, 6, 18, tzinfo=timezone.utc))

    assert result.valid is True
    assert result.status == "ACTIVE"


def test_missing_license_blocks():
    result = validate_license_record(None)

    assert result.valid is False
    assert result.status == "BLOCKED"
    assert result.reason_codes == ("MISSING_LICENSE",)


def test_expired_suspended_and_revoked_license_block():
    now = datetime(2026, 6, 18, tzinfo=timezone.utc)

    assert "EXPIRED_LICENSE" in validate_license_record(license_record(expires_at="2026-01-01T00:00:00Z"), now=now).reason_codes
    assert "SUSPENDED_LICENSE" in validate_license_record(license_record(license_state="SUSPENDED"), now=now).reason_codes
    assert "REVOKED_LICENSE" in validate_license_record(license_record(license_state="REVOKED"), now=now).reason_codes


def test_unknown_tier_and_missing_audit_block():
    result = validate_license_record(license_record(license_tier="PERSONAL", audit_hash=""))

    assert "UNKNOWN_LICENSE_TIER" in result.reason_codes
    assert "AUDIT_EXPORT_NOT_LICENSED" in result.reason_codes


def test_sensitive_data_marker_blocks():
    record = license_record()
    record["note"] = "credential private_key"

    result = validate_license_record(record)

    assert "SENSITIVE_DATA_LOGGING_FORBIDDEN" in result.reason_codes


def test_fail_closed_reason_code_registry_contains_required_codes():
    assert "MISSING_LICENSE" in FAIL_CLOSED_REASON_CODES
    assert "GOVERNANCE_MODULE_NOT_LICENSED" in FAIL_CLOSED_REASON_CODES
