from __future__ import annotations

import pytest

from governance.orchestrator_state_model import (
    ORCHESTRATOR_STATE_MODEL_VERSION,
    OrchestratorState,
    evaluate_transition,
    state_model_contract,
)


pytestmark = pytest.mark.governance


def test_state_model_declares_required_states_and_terminal_states() -> None:
    contract = state_model_contract()

    assert contract["policy_version"] == ORCHESTRATOR_STATE_MODEL_VERSION
    assert contract["states"] == [state.value for state in OrchestratorState]
    assert contract["terminal_states"] == ["MERGE_ELIGIBLE", "BLOCKED"]
    assert contract["fail_closed_state"] == "BLOCKED"


def test_nominal_state_progression_requires_human_review_before_merge_eligibility() -> None:
    sequence = [
        "IDLE",
        "DETECTED_FAILURE",
        "CLASSIFIED",
        "PB_CREATED",
        "BRANCH_CREATED",
        "PATCH_PROPOSED",
        "VALIDATION_RUNNING",
        "VALIDATION_PASSED",
        "HUMAN_REVIEW_REQUIRED",
        "MERGE_ELIGIBLE",
    ]

    for current, target in zip(sequence, sequence[1:]):
        decision = evaluate_transition(current, target)
        assert decision.decision == "ALLOW"
        assert decision.reason == "TRANSITION_ALLOWED"


def test_validation_failure_can_only_block() -> None:
    assert evaluate_transition("VALIDATION_RUNNING", "VALIDATION_FAILED").decision == "ALLOW"
    blocked = evaluate_transition("VALIDATION_FAILED", "MERGE_ELIGIBLE")

    assert blocked.decision == "BLOCKED"
    assert blocked.reason == "TRANSITION_NOT_ALLOWED"


def test_invalid_or_unknown_states_fail_closed() -> None:
    decision = evaluate_transition("VALIDATION_PASSED", "AUTO_MERGED")

    assert decision.decision == "BLOCKED"
    assert decision.reason == "UNKNOWN_ORCHESTRATOR_STATE"


def test_merge_eligible_and_blocked_are_terminal() -> None:
    assert evaluate_transition("MERGE_ELIGIBLE", "IDLE").decision == "BLOCKED"
    assert evaluate_transition("BLOCKED", "IDLE").decision == "BLOCKED"
