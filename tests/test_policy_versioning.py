from __future__ import annotations

import pytest

from governance.policy_versioning import validate_policy_transition


pytestmark = pytest.mark.governance


@pytest.mark.parametrize(
    ("source", "target"),
    [
        ("DRAFT", "REVIEW_REQUIRED"),
        ("REVIEW_REQUIRED", "APPROVED"),
        ("APPROVED", "ACTIVE"),
        ("ACTIVE", "DEPRECATED"),
        ("DEPRECATED", "RETIRED"),
    ],
)
def test_allowed_transitions(source, target):
    result = validate_policy_transition(source, target)

    assert result["transition_status"] == "ALLOWED"
    assert result["auto_promoted"] is False


def test_invalid_transition_blocks():
    result = validate_policy_transition("DRAFT", "ACTIVE")

    assert result["transition_status"] == "BLOCKED"
    assert "POLICY_TRANSITION_INVALID:DRAFT->ACTIVE" in result["reason_codes"]


def test_unknown_state_blocks():
    result = validate_policy_transition("AUTO_PROMOTED", "ACTIVE")

    assert result["transition_status"] == "BLOCKED"
    assert "POLICY_FROM_STATUS_UNKNOWN:AUTO_PROMOTED" in result["reason_codes"]
