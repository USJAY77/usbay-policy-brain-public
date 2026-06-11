from __future__ import annotations

from pathlib import Path

from runtime.computer_use.mac_dry_run_loop import simulate_controlled_mac_dry_run


REPORT = Path("governance/evidence/pb246_250/controlled_mac_dry_run_report.md")


def test_controlled_mac_dry_run_simulates_full_loop_without_execution() -> None:
    result = simulate_controlled_mac_dry_run()
    assert result["steps"] == [
        "screenshot_metadata",
        "screen_classification",
        "risk_score",
        "proposed_action",
        "approval_required",
        "audit_evidence",
    ]
    assert result["decision"] == "HUMAN_APPROVAL_REQUIRED"
    assert result["audit_hash"]
    assert result["real_execution_performed"] is False
    assert result["pyautogui_execution_performed"] is False
    assert result["browser_calls_performed"] is False
    assert result["external_api_calls_performed"] is False
    assert result["raw_screenshot_stored"] is False


def test_controlled_mac_dry_run_report_documents_prohibitions() -> None:
    text = REPORT.read_text(encoding="utf-8")
    assert "Must not click, type, scroll, or open apps" in text
    assert "No pyautogui" in text
    assert "No browser calls" in text
    assert "No external API calls" in text
    assert "No raw screenshots stored" in text
