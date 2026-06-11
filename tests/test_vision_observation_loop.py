from __future__ import annotations

from runtime.computer_use.mac_dry_run_loop import run_observation_loop


def test_observation_loop_runs_deterministic_steps_without_external_api() -> None:
    result = run_observation_loop({"title": "GitHub pull request"})
    assert result["steps"] == [
        "observe_screen",
        "classify_screen",
        "detect_sensitive_markers",
        "score_risk",
        "policy_decision",
    ]
    assert result["external_vision_api_calls"] is False
    assert result["raw_screenshot_stored"] is False


def test_observation_loop_unknown_screen_fails_closed() -> None:
    result = run_observation_loop({"title": "unrecognized pixels"})
    assert result["policy_decision"] == "FAIL_CLOSED"
    assert result["classification"]["screen_class"] == "UNKNOWN"


def test_observation_loop_sensitive_screen_blocks() -> None:
    result = run_observation_loop({"title": "bank payment"})
    assert result["policy_decision"] == "BLOCKED"
    assert result["risk"]["risk_level"] == "CRITICAL"
