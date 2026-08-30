from runtime.computer_use.decision_engine import DecisionEngine
from runtime.computer_use.policy_enforcement import PolicyEnforcer


def _engine() -> DecisionEngine:
    return DecisionEngine(PolicyEnforcer({"policy_version": "pb168", "allowed_actions": ["read_screen", "click"]}))


def test_low_risk_allows() -> None:
    decision = _engine().decide(
        action_type="read_screen",
        target="screen",
        screen_summary="dashboard",
        provider_response={"status": "ALLOW"},
        approval_state=None,
        policy_version="pb168",
    )

    assert decision.decision == "ALLOW"
    assert decision.risk_level == "LOW_RISK"


def test_medium_risk_human_review() -> None:
    decision = _engine().decide(
        action_type="click",
        target="settings",
        screen_summary="settings page",
        provider_response={"status": "ALLOW"},
        approval_state=None,
        policy_version="pb168",
    )

    assert decision.decision == "HUMAN_REVIEW"
    assert decision.risk_level == "MEDIUM_RISK"


def test_high_risk_human_review() -> None:
    decision = _engine().decide(
        action_type="click",
        target="GitHub merge",
        screen_summary="pull request",
        provider_response={"status": "ALLOW"},
        approval_state=None,
        policy_version="pb168",
    )

    assert decision.decision == "HUMAN_REVIEW"
    assert decision.risk_level == "HIGH_RISK"


def test_missing_policy_fail_closed() -> None:
    decision = DecisionEngine(PolicyEnforcer(None)).decide(
        action_type="read_screen",
        target="screen",
        screen_summary="dashboard",
        provider_response={"status": "ALLOW"},
        approval_state=None,
        policy_version="pb168",
    )

    assert decision.decision == "FAIL_CLOSED"


def test_unknown_input_fail_closed() -> None:
    decision = _engine().decide(
        action_type=None,
        target="screen",
        screen_summary="dashboard",
        provider_response={"status": "ALLOW"},
        approval_state=None,
        policy_version="pb168",
    )

    assert decision.decision == "FAIL_CLOSED"

