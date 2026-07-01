from __future__ import annotations

from runtime_trust.pilot_activation import evaluate_pilot_activation, pilot_activation_contract_json


def test_pilot_activation_contract_defaults_blocked_and_contract_only() -> None:
    contract = pilot_activation_contract_json()
    assert contract["default_state"] == "BLOCKED"
    assert contract["activation_execution_allowed"] is False


def test_pilot_activation_blocks_when_any_condition_missing() -> None:
    result = evaluate_pilot_activation(
        policy_approved=True,
        human_approval_approved=False,
        attestation_valid=True,
        nonce_valid=True,
        replay_protection_clean=True,
        runtime_ledger_bound=False,
    )
    assert result["decision"] == "BLOCKED"
    assert "HUMAN_APPROVAL_NOT_APPROVED" in result["gaps"]
    assert "RUNTIME_LEDGER_NOT_BOUND" in result["gaps"]


def test_pilot_activation_ready_for_review_only_when_all_conditions_clean() -> None:
    result = evaluate_pilot_activation(
        policy_approved=True,
        human_approval_approved=True,
        attestation_valid=True,
        nonce_valid=True,
        replay_protection_clean=True,
        runtime_ledger_bound=True,
    )
    assert result["decision"] == "READY_FOR_REVIEW"
    assert result["activation_execution_allowed"] is False
