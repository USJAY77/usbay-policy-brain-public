from __future__ import annotations

import pytest

from governance.clamav_governance import evaluate_clamav_governance


pytestmark = pytest.mark.governance


def test_clamav_governance_valid_when_engine_and_policy_valid():
    result = evaluate_clamav_governance({"scan_engine": "CLAMAV", "clamav_valid": True, "scan_policy": True})

    assert result["clamav_status"] == "VALID"
    assert result["malware_execution_enabled"] is False


def test_clamav_governance_blocks_unknown_untrusted_and_detection():
    result = evaluate_clamav_governance(
        {"scan_engine": "YARA", "clamav_valid": False, "scan_policy": False, "malware_detected": True}
    )

    assert "UNKNOWN_SCAN_ENGINE" in result["reason_codes"]
    assert "UNTRUSTED_SCAN_RESULT" in result["reason_codes"]
    assert "MISSING_SCAN_POLICY" in result["reason_codes"]
    assert "MALWARE_DETECTED" in result["reason_codes"]
