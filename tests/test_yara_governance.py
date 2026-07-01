from __future__ import annotations

import pytest

from governance.yara_governance import evaluate_yara_governance


pytestmark = pytest.mark.governance


def test_yara_governance_valid_when_engine_and_policy_valid():
    result = evaluate_yara_governance({"scan_engine": "YARA", "yara_valid": True, "scan_policy": True})

    assert result["yara_status"] == "VALID"
    assert result["file_modification_enabled"] is False


def test_yara_governance_blocks_unknown_untrusted_and_match():
    result = evaluate_yara_governance(
        {"scan_engine": "CLAMAV", "yara_valid": False, "scan_policy": False, "yara_match_detected": True}
    )

    assert "UNKNOWN_SCAN_ENGINE" in result["reason_codes"]
    assert "UNTRUSTED_SCAN_RESULT" in result["reason_codes"]
    assert "MISSING_SCAN_POLICY" in result["reason_codes"]
    assert "YARA_MATCH_DETECTED" in result["reason_codes"]
