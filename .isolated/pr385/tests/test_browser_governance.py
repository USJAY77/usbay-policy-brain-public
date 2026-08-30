from __future__ import annotations

import pytest

from governance.browser_governance import evaluate_browser_governance


pytestmark = pytest.mark.governance


def test_browser_governance_valid_when_no_control():
    result = evaluate_browser_governance({"browser_control": False})

    assert result["browser_status"] == "VALID"
    assert result["browser_control_enabled"] is False


def test_browser_governance_blocks_control():
    result = evaluate_browser_governance({"browser_control": True})

    assert result["browser_status"] == "BLOCKED"
    assert result["reason_codes"] == ["BROWSER_CONTROL_FORBIDDEN"]
