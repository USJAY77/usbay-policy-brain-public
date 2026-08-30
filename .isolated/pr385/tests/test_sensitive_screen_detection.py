from __future__ import annotations

from runtime.computer_use.vision_governance import detect_sensitive_screen


def test_sensitive_screen_detection_blocks_password_and_token_markers() -> None:
    result = detect_sensitive_screen({"text": "password token private key"})
    assert result["decision"] == "BLOCKED"
    assert "password" in result["markers"]
    assert result["raw_screenshot_stored"] is False


def test_sensitive_screen_detection_requires_human_approval_for_personal_data() -> None:
    result = detect_sensitive_screen({"text": "personal data profile"})
    assert result["decision"] == "HUMAN_APPROVAL_REQUIRED"
    assert result["status"] == "HUMAN_APPROVAL_REQUIRED"


def test_sensitive_screen_detection_never_logs_raw_screenshot() -> None:
    result = detect_sensitive_screen({"text": "safe workspace", "raw_screenshot": "do-not-store"})
    assert result["raw_screenshot_stored"] is False
    assert "raw_screenshot" not in result
