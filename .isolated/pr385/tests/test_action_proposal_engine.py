from __future__ import annotations

from runtime.computer_use.mac_dry_run_loop import propose_dry_run_action


def test_action_proposal_generates_policy_decision_for_supported_actions() -> None:
    action = propose_dry_run_action(action_id="a1", action_type="click", screen_metadata={"title": "GitHub pull request"})
    assert action["action_id"] == "a1"
    assert action["action_type"] == "click"
    assert action["policy_decision"] == action["decision"]
    assert action["audit_hash"]
    assert action["real_execution_performed"] is False


def test_action_proposal_high_risk_requires_human_approval() -> None:
    action = propose_dry_run_action(action_id="a2", action_type="type_text", screen_metadata={"title": "login screen"})
    assert action["risk_level"] == "HIGH"
    assert action["decision"] == "HUMAN_APPROVAL_REQUIRED"


def test_action_proposal_critical_risk_blocks() -> None:
    action = propose_dry_run_action(action_id="a3", action_type="type_text", screen_metadata={"title": "payment screen"})
    assert action["risk_level"] == "CRITICAL"
    assert action["decision"] == "BLOCKED"


def test_action_proposal_unknown_action_blocks() -> None:
    action = propose_dry_run_action(action_id="a4", action_type="drag", screen_metadata={"title": "GitHub pull request"})
    assert action["decision"] == "BLOCKED"
