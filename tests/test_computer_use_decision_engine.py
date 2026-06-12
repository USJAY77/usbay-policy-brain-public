from __future__ import annotations

from runtime.computer_use.decision_engine import ComputerUseDecisionEngine


def _provider(status: str = "ALLOW") -> dict[str, object]:
    return {
        "provider": "mock",
        "status": status,
        "screen_summary": "read-only status",
        "proposed_action": {"type": "read_screen", "target": "status", "risk": "LOW"},
        "requires_human_approval": False,
        "reason": "test",
        "audit": {
            "raw_screenshot_stored": False,
            "provider_call_recorded": True,
            "policy_checked": True,
        },
    }


def _contract(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "action_type": "read_screen",
        "target": "governance status panel",
        "screen_summary": "read-only governance status",
        "provider_response": _provider(),
        "approval_state": "NONE",
        "policy_version": "computer-use-policy-v1",
    }
    payload.update(overrides)
    return payload


def test_low_risk_allows_with_audit_fields() -> None:
    decision = ComputerUseDecisionEngine().decide(_contract())

    assert decision.decision == "ALLOW"
    assert decision.reason == "LOW_RISK"
    assert decision.risk_level == "LOW"
    assert decision.policy_version == "computer-use-policy-v1"
    assert decision.decision_id.startswith("cud-")
    assert len(decision.audit_hash) == 64
    assert decision.timestamp.endswith("Z")


def test_medium_risk_requires_human_review() -> None:
    decision = ComputerUseDecisionEngine().decide(
        _contract(
            action_type="click",
            target="ordinary settings toggle",
            screen_summary="non-sensitive settings page",
        )
    )

    assert decision.decision == "HUMAN_REVIEW"
    assert decision.reason == "MEDIUM_RISK"
    assert decision.risk_level == "MEDIUM"


def test_high_risk_requires_human_review() -> None:
    decision = ComputerUseDecisionEngine().decide(
        _contract(
            action_type="click",
            target="repository deletion",
            screen_summary="delete repository button",
        )
    )

    assert decision.decision == "HUMAN_REVIEW"
    assert decision.reason == "HIGH_RISK"
    assert decision.risk_level == "HIGH"


def test_unknown_input_fails_closed() -> None:
    decision = ComputerUseDecisionEngine().decide(_contract(action_type="", target="target"))

    assert decision.decision == "FAIL_CLOSED"
    assert decision.reason == "UNKNOWN"
    assert decision.risk_level == "UNKNOWN"


def test_missing_policy_fails_closed() -> None:
    decision = ComputerUseDecisionEngine().decide(_contract(policy_version=""))

    assert decision.decision == "FAIL_CLOSED"
    assert decision.reason == "MISSING_POLICY"
    assert decision.risk_level == "UNKNOWN"


def test_unsupported_action_blocks() -> None:
    decision = ComputerUseDecisionEngine().decide(_contract(action_type="drag"))

    assert decision.decision == "BLOCK"
    assert decision.reason == "UNSUPPORTED_ACTION"
    assert decision.risk_level == "UNKNOWN"


def test_provider_fail_closed_fails_closed() -> None:
    decision = ComputerUseDecisionEngine().decide(_contract(provider_response=_provider("FAIL_CLOSED")))

    assert decision.decision == "FAIL_CLOSED"
    assert decision.reason == "PROVIDER_FAIL_CLOSED"


def test_provider_block_blocks() -> None:
    decision = ComputerUseDecisionEngine().decide(_contract(provider_response=_provider("BLOCK")))

    assert decision.decision == "BLOCK"
    assert decision.reason == "PROVIDER_BLOCKED_ACTION"


def test_malformed_provider_response_fails_closed() -> None:
    decision = ComputerUseDecisionEngine().decide(_contract(provider_response={"status": "MAYBE"}))

    assert decision.decision == "FAIL_CLOSED"
    assert decision.reason == "PROVIDER_RESPONSE_MALFORMED"


def test_missing_required_contract_input_fails_closed() -> None:
    payload = _contract()
    payload.pop("screen_summary")

    decision = ComputerUseDecisionEngine().decide(payload)

    assert decision.decision == "FAIL_CLOSED"
    assert decision.reason == "ACTION_CONTRACT_REQUIRED_INPUT_MISSING:screen_summary"


def test_denied_approval_state_blocks() -> None:
    decision = ComputerUseDecisionEngine().decide(_contract(approval_state="DENIED"))

    assert decision.decision == "BLOCK"
    assert decision.reason == "APPROVAL_STATE_BLOCKED"
