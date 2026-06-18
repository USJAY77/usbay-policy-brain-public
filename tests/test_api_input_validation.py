from __future__ import annotations

import pytest

from governance.api_input_validation import evaluate_api_input_validation


pytestmark = pytest.mark.governance


def test_api_input_validation_valid_when_policy_exists():
    result = evaluate_api_input_validation({"input_validation_policy": True})

    assert result["api_input_validation_status"] == "VALID"
    assert result["network_access_enabled"] is False


def test_api_input_validation_blocks_missing_policy_ssrf_and_sensitive_exposure():
    result = evaluate_api_input_validation(
        {"input_validation_policy": False, "ssrf_risk": True, "sensitive_data_exposure": True}
    )

    assert "MISSING_INPUT_VALIDATION_POLICY" in result["reason_codes"]
    assert "SSRF_RISK_DETECTED" in result["reason_codes"]
    assert "SENSITIVE_DATA_EXPOSURE" in result["reason_codes"]
