from runtime.computer_use.runtime_controller import RuntimeController, RuntimeRequest


def test_runtime_controller_allows_policy_approved_low_risk_state() -> None:
    controller = RuntimeController()
    state = controller.create_state(
        RuntimeRequest(
            action_type="read_screen",
            target="current screen",
            required_capability="screen_read",
            policy_version="pb167",
        )
    )

    decision = controller.authorize(
        state.action_id,
        policy_decision="ALLOW",
        approval_valid=False,
        policy_version="pb167",
    )

    assert decision.decision == "ALLOW"
    assert decision.state == "AUTHORIZED"
    assert decision.audit_hash


def test_runtime_controller_fail_closed_on_missing_policy() -> None:
    controller = RuntimeController()
    state = controller.create_state(
        RuntimeRequest(
            action_type="click",
            target="unknown",
            required_capability="mouse",
            policy_version="pb167",
        )
    )

    decision = controller.authorize(state.action_id, policy_decision=None, policy_version="pb167")

    assert decision.decision == "FAIL_CLOSED"
    assert decision.reason == "missing_policy_decision"


def test_runtime_controller_requires_approval_for_human_review() -> None:
    controller = RuntimeController()
    state = controller.create_state(
        RuntimeRequest(
            action_type="click",
            target="deploy",
            required_capability="mouse",
            policy_version="pb167",
        )
    )

    decision = controller.authorize(state.action_id, policy_decision="HUMAN_REVIEW", policy_version="pb167")

    assert decision.decision == "HUMAN_REVIEW"
    assert decision.state == "HUMAN_REVIEW"


def test_runtime_controller_fail_closed_on_policy_version_mismatch() -> None:
    controller = RuntimeController()
    state = controller.create_state(
        RuntimeRequest(
            action_type="read_screen",
            target="screen",
            required_capability="screen_read",
            policy_version="pb167",
        )
    )

    decision = controller.authorize(state.action_id, policy_decision="ALLOW", policy_version="other")

    assert decision.decision == "FAIL_CLOSED"
    assert decision.reason == "policy_version_mismatch"

