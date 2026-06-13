from runtime.computer_use.risk_classifier import classify_risk


def test_low_risk_read_screen() -> None:
    assert classify_risk("read_screen", "current screen") == "LOW_RISK"


def test_medium_risk_click() -> None:
    assert classify_risk("click", "settings") == "MEDIUM_RISK"


def test_high_risk_merge_target() -> None:
    assert classify_risk("click", "GitHub merge pull request") == "HIGH_RISK"


def test_unknown_missing_action() -> None:
    assert classify_risk(None, "screen") == "UNKNOWN"

