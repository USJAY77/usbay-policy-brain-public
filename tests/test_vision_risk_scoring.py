from __future__ import annotations

from runtime.computer_use.vision_governance import score_vision_risk


def test_low_risk_safe_workspace_is_verified_without_approval() -> None:
    result = score_vision_risk("SAFE_WORKSPACE", [])
    assert result["risk_level"] == "LOW"
    assert result["approval_required"] is False
    assert result["decision"] == "VERIFIED"


def test_high_risk_login_requires_human_approval() -> None:
    result = score_vision_risk("LOGIN_SCREEN", [])
    assert result["risk_level"] == "HIGH"
    assert result["approval_required"] is True
    assert result["decision"] == "HUMAN_APPROVAL_REQUIRED"


def test_critical_payment_blocks_execution() -> None:
    result = score_vision_risk("PAYMENT_SCREEN", ["payment"])
    assert result["risk_level"] == "CRITICAL"
    assert result["approval_required"] is True
    assert result["decision"] == "BLOCKED"
    assert result["raw_screenshot_stored"] is False
