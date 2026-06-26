from __future__ import annotations

from pilot.controlled_live_pilot import controlled_live_pilot_contract_json, evaluate_pilot_readiness


def test_controlled_live_pilot_defaults_blocked_for_limited_workflow() -> None:
    contract = controlled_live_pilot_contract_json()
    assert contract["workflow"] == ["GitHub", "USBAY Gateway", "Human Approval", "Codex"]
    assert contract["state"] == "BLOCKED"
    assert contract["human_approval_required"] is True
    assert contract["live_execution_allowed"] is False


def test_pilot_readiness_blocks_without_human_approval() -> None:
    result = evaluate_pilot_readiness(credential_verified=True, policy_hash_verified=True, deployment_attested=True)
    assert result["decision"] == "BLOCKED"
    assert "HUMAN_APPROVAL_REQUIRED" in result["gaps"]
    assert result["live_execution_allowed"] is False


def test_pilot_readiness_can_reach_review_without_live_execution() -> None:
    result = evaluate_pilot_readiness(
        credential_verified=True,
        human_approved=True,
        policy_hash_verified=True,
        deployment_attested=True,
    )
    assert result["decision"] == "READY_FOR_REVIEW"
    assert result["state"] == "READY_FOR_REVIEW"
    assert result["production_activation_allowed"] is False
