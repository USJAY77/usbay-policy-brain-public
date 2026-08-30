from __future__ import annotations

from runtime.computer_use.controlled_mac_execution import create_execution_evidence


def test_execution_evidence_contains_required_fields_without_raw_screenshot() -> None:
    evidence = create_execution_evidence(
        action_id="a1",
        approval_id="approval-1",
        screen_hash="f" * 64,
        screen_class="CODE_EDITOR",
        risk_level="LOW",
        policy_hash="a" * 64,
        decision="BLOCKED",
    )
    for field in (
        "action_id",
        "approval_id",
        "screen_hash",
        "screen_class",
        "risk_level",
        "policy_hash",
        "decision",
        "executed",
        "blocked_reason",
        "audit_hash",
    ):
        assert field in evidence
    assert evidence["executed"] is False
    assert evidence["raw_screenshot_stored"] is False
    assert evidence["sensitive_data_stored"] is False


def test_execution_evidence_never_claims_execution_even_if_requested() -> None:
    evidence = create_execution_evidence(
        action_id="a2",
        approval_id="approval-2",
        screen_hash="f" * 64,
        screen_class="GITHUB_PR",
        risk_level="MEDIUM",
        policy_hash="a" * 64,
        decision="READY_FOR_REVIEW",
        executed=True,
    )
    assert evidence["executed"] is False
    assert evidence["blocked_reason"] == "EXECUTION_NOT_ACTIVATED"
