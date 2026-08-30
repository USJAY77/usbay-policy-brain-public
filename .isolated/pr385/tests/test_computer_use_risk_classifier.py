from __future__ import annotations

import pytest

from runtime.computer_use.risk_classifier import classify_risk


def test_low_risk_read_screen_classifies_low() -> None:
    result = classify_risk(
        action_type="read_screen",
        target="dashboard status panel",
        screen_summary="read-only governance status",
    )

    assert result.risk_level == "LOW"
    assert result.reason == "LOW_RISK_ACTION"


@pytest.mark.parametrize("action_type", ["click", "type", "open_url"])
def test_mutating_or_navigating_actions_classify_medium(action_type: str) -> None:
    result = classify_risk(
        action_type=action_type,
        target="ordinary form control",
        screen_summary="non-sensitive settings page",
    )

    assert result.risk_level == "MEDIUM"
    assert result.reason == "MUTATING_OR_NAVIGATING_ACTION"


@pytest.mark.parametrize(
    "target",
    [
        "browser login",
        "credential entry",
        "password fields",
        "token handling",
        "repository deletion",
        "deployment actions",
        "branch deletion",
        "system settings changes",
        "file deletion",
    ],
)
def test_high_risk_examples_classify_high(target: str) -> None:
    result = classify_risk(action_type="click", target=target, screen_summary="screen contains high risk action")

    assert result.risk_level == "HIGH"
    assert result.reason == "HIGH_RISK_TARGET"


def test_unsupported_action_classifies_unknown() -> None:
    result = classify_risk(action_type="drag", target="canvas", screen_summary="unsupported action")

    assert result.risk_level == "UNKNOWN"
    assert result.reason == "UNSUPPORTED_ACTION"


def test_missing_classifier_input_classifies_unknown() -> None:
    result = classify_risk(action_type="", target="target", screen_summary="summary")

    assert result.risk_level == "UNKNOWN"
    assert result.reason == "RISK_INPUT_MISSING"
