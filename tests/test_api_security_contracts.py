from __future__ import annotations

import pytest

from governance.api_security_contracts import REASON_CODES, build_api_security_record, validate_api_security_record


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


def test_valid_api_security_contract():
    result = validate_api_security_record(api_record())

    assert result.valid is True
    assert result.status == "GOVERNED"


def test_unknown_api_and_missing_inventory_block():
    result = validate_api_security_record(api_record(api_id="", inventory_record=False))

    assert "UNKNOWN_API" in result.reason_codes
    assert "MISSING_API_INVENTORY" in result.reason_codes


def test_missing_security_policies_block():
    result = validate_api_security_record(
        api_record(access_control_policy=False, rate_limit_policy=False, input_validation_policy=False)
    )

    assert "MISSING_ACCESS_CONTROL" in result.reason_codes
    assert "MISSING_RATE_LIMIT_POLICY" in result.reason_codes
    assert "MISSING_INPUT_VALIDATION_POLICY" in result.reason_codes


def test_sensitive_ssrf_bypass_and_external_api_block():
    result = validate_api_security_record(
        api_record(
            classification="EXTERNAL",
            external_api_governed=False,
            ssrf_risk=True,
            governance_bypass=True,
            sensitive_data_exposure=True,
        )
    )

    assert "EXTERNAL_API_NOT_GOVERNED" in result.reason_codes
    assert "SSRF_RISK_DETECTED" in result.reason_codes
    assert "GOVERNANCE_BYPASS_ATTEMPT" in result.reason_codes
    assert "SENSITIVE_DATA_EXPOSURE" in result.reason_codes


def test_reason_code_registry_contains_required_codes():
    assert "UNKNOWN_API" in REASON_CODES
    assert "EXTERNAL_API_NOT_GOVERNED" in REASON_CODES
