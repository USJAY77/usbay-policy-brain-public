from __future__ import annotations

import pytest

from governance.human_approval_gate_contract import (
    HUMAN_APPROVAL_GATE_VERSION,
    evaluate_human_approval,
    human_approval_gate_contract,
)


pytestmark = pytest.mark.governance


def _approval() -> dict[str, object]:
    return {
        "validation_passed": True,
        "blast_radius": "contract-only",
        "changed_files": ["governance/human_approval_gate_contract.py"],
        "policy_version": HUMAN_APPROVAL_GATE_VERSION,
        "human_reviewer": "human-reviewer",
        "approval_timestamp": "2026-06-14T00:00:00Z",
    }


def test_human_approval_contract_declares_required_evidence_and_blocks() -> None:
    contract = human_approval_gate_contract()

    assert contract["policy_version"] == HUMAN_APPROVAL_GATE_VERSION
    assert "validation_passed" in contract["required_evidence"]
    assert "human_reviewer" in contract["required_evidence"]
    assert "self_approval" in contract["blocked"]
    assert contract["merge_decision_without_human_approval"] == "BLOCKED"


def test_complete_human_approval_allows_publication_readiness_not_merge() -> None:
    decision = evaluate_human_approval(_approval(), actor="codex")

    assert decision.decision == "APPROVED_FOR_PUBLICATION"
    assert decision.reason_codes == ()


def test_missing_approval_evidence_blocks() -> None:
    decision = evaluate_human_approval(None, actor="codex")

    assert decision.decision == "BLOCKED"
    assert decision.reason_codes == ("HUMAN_APPROVAL_EVIDENCE_MISSING",)


def test_self_approval_and_failed_validation_block() -> None:
    approval = _approval()
    approval["human_reviewer"] = "codex"
    approval["validation_passed"] = False

    decision = evaluate_human_approval(approval, actor="codex")

    assert decision.decision == "BLOCKED"
    assert "SELF_APPROVAL_BLOCKED" in decision.reason_codes
    assert "VALIDATION_NOT_PASSED" in decision.reason_codes


def test_automatic_merge_and_production_execution_are_blocked() -> None:
    decision = evaluate_human_approval(
        _approval(),
        actor="codex",
        auto_merge_requested=True,
        production_execution_requested=True,
    )

    assert decision.decision == "BLOCKED"
    assert "AUTOMATIC_MERGE_BLOCKED" in decision.reason_codes
    assert "AUTOMATIC_PRODUCTION_EXECUTION_BLOCKED" in decision.reason_codes
