from __future__ import annotations

from runtime.computer_use.mac_dry_run_loop import capture_screenshot_metadata, screenshot_capture_contract_json


def test_screenshot_capture_contract_stores_only_metadata_fields() -> None:
    contract = screenshot_capture_contract_json()
    assert contract["raw_screenshot_storage"] == "DISABLED"
    assert contract["stored_fields"] == ["screenshot_hash", "timestamp", "screen_class", "risk_level", "policy_hash"]
    assert contract["pyautogui_execution_allowed"] is False


def test_screenshot_capture_metadata_never_stores_raw_screenshot() -> None:
    result = capture_screenshot_metadata(screen_metadata={"title": "GitHub pull request"})
    assert result["decision"] == "VERIFIED"
    assert result["screenshot_hash"]
    assert result["raw_screenshot_stored"] is False
    assert "raw_screenshot" not in result


def test_screenshot_capture_blocks_sensitive_screen() -> None:
    result = capture_screenshot_metadata(screen_metadata={"title": "payment screen"})
    assert result["decision"] == "BLOCKED"
    assert result["screen_class"] == "PAYMENT_SCREEN"
    assert result["risk_level"] == "CRITICAL"
