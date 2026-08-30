from __future__ import annotations

import pytest

from governance.api_rate_limit_governance import evaluate_api_rate_limit


pytestmark = pytest.mark.governance


def test_api_rate_limit_valid_when_policy_exists():
    result = evaluate_api_rate_limit({"rate_limit_policy": True})

    assert result["api_rate_limit_status"] == "VALID"
    assert result["firewall_modification_enabled"] is False


def test_api_rate_limit_blocks_missing_policy():
    result = evaluate_api_rate_limit({"rate_limit_policy": False})

    assert result["api_rate_limit_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_RATE_LIMIT_POLICY"]
