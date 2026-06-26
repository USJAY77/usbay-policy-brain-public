from orchestration.cross_system_orchestrator import DEFAULT_POLICY_HASH, WORKFLOW
from pilot_operations.live_pilot_authorization import (
    evaluate_pilot_scope_authorization,
    pilot_scope_authorization_contract_json,
)


def _scope(**overrides):
    payload = {
        "policy_hash": DEFAULT_POLICY_HASH,
        "workflow": list(WORKFLOW),
        "human_board_approval_required": True,
        "production_activation_allowed": False,
        "connector_activation_allowed": False,
        "browser_automation_allowed": False,
        "desktop_automation_allowed": False,
        "terminal_write_execution_allowed": False,
        "external_api_calls_allowed": False,
    }
    payload.update(overrides)
    return payload


def test_scope_authorization_contract_is_documentation_only():
    contract = pilot_scope_authorization_contract_json()

    assert contract["decision"] == "READY_FOR_REVIEW"
    assert contract["scope"]["default_state"] == "BLOCKED"
    assert contract["production_activation_allowed"] is False
    assert contract["external_api_calls_allowed"] is False


def test_malformed_scope_fails_closed():
    result = evaluate_pilot_scope_authorization(None)

    assert result["decision"] == "FAIL_CLOSED"
    assert result["state"] == "BLOCKED"


def test_scope_with_activation_flag_fails_closed():
    result = evaluate_pilot_scope_authorization(_scope(desktop_automation_allowed=True))

    assert result["decision"] == "FAIL_CLOSED"
    assert "DESKTOP_AUTOMATION_ALLOWED_MUST_BE_FALSE" in result["gaps"]


def test_valid_scope_requires_board_review_without_activation():
    result = evaluate_pilot_scope_authorization(_scope())

    assert result["decision"] == "READY_FOR_REVIEW"
    assert result["state"] == "BOARD_REVIEW_REQUIRED"
    assert result["activation_allowed"] is False
