from __future__ import annotations

from runtime.computer_use.vision_governance import classify_screen


def test_screen_classifier_identifies_github_pr() -> None:
    result = classify_screen({"title": "GitHub pull request review"})
    assert result["decision"] == "VERIFIED"
    assert result["screen_class"] == "GITHUB_PR"
    assert result["raw_screenshot_stored"] is False


def test_screen_classifier_identifies_notion_page() -> None:
    result = classify_screen({"title": "Notion workspace page"})
    assert result["screen_class"] == "NOTION_PAGE"


def test_screen_classifier_unknown_fails_closed() -> None:
    result = classify_screen({"title": "ambiguous pixels"})
    assert result["decision"] == "FAIL_CLOSED"
    assert result["screen_class"] == "UNKNOWN"
