from __future__ import annotations

from runtime.computer_use.controlled_mac_execution import live_mac_pilot_window_contract_json


def test_live_mac_pilot_window_defaults_blocked() -> None:
    window = live_mac_pilot_window_contract_json()
    assert window["status"] == "BLOCKED"
    assert window["live_execution_activation_allowed"] is False
    assert window["start_time"]
    assert window["end_time"]


def test_live_mac_pilot_window_declares_allowed_and_blocked_apps() -> None:
    window = live_mac_pilot_window_contract_json()
    assert "Code" in window["allowed_apps"]
    assert "Browser" in window["blocked_apps"]
    assert set(window["allowed_actions"]) == {"click", "type_text", "press_key", "scroll", "open_app"}
