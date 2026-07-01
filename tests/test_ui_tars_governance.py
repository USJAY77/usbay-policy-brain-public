from __future__ import annotations

import pytest

from governance.ui_tars_governance import evaluate_ui_tars_governance


pytestmark = pytest.mark.governance


def test_ui_tars_governance_valid_when_registered_and_passive():
    result = evaluate_ui_tars_governance({"agent_type": "UI_TARS", "registered_agent": True})

    assert result["ui_tars_status"] == "VALID"
    assert result["mouse_control_enabled"] is False
    assert result["keyboard_control_enabled"] is False


def test_ui_tars_governance_blocks_unregistered_input_control():
    result = evaluate_ui_tars_governance({"agent_type": "UI_TARS", "registered_agent": False, "mouse_control": True, "keyboard_control": True})

    assert "UNREGISTERED_AGENT" in result["reason_codes"]
    assert "MOUSE_CONTROL_FORBIDDEN" in result["reason_codes"]
    assert "KEYBOARD_CONTROL_FORBIDDEN" in result["reason_codes"]
