from __future__ import annotations

from dataclasses import replace

from runtime.computer_use.audit_chain import CHAIN_BROKEN, VALID
from runtime.computer_use.decision_engine import ComputerUseExecutionDecision
from runtime.computer_use.decision_provenance import (
    chain_is_broken,
    record_decision_provenance,
    verify_decision_provenance,
)


def _decision(index: int, decision: str = "ALLOW", risk_level: str = "LOW") -> ComputerUseExecutionDecision:
    payload = {
        "decision_id": f"cud-{index}",
        "decision": decision,
        "reason": "LOW_RISK" if risk_level == "LOW" else "HIGH_RISK",
        "risk_level": risk_level,
        "policy_version": "computer-use-policy-v1",
        "timestamp": f"2026-06-10T00:01:0{index}Z",
    }
    return ComputerUseExecutionDecision(audit_hash="a" * 64, **payload)


def test_records_decision_provenance_with_chain_output() -> None:
    result = record_decision_provenance([], _decision(0), approval_state="NONE")

    assert result.record.decision_id == "cud-0"
    assert result.record.approval_state == "NONE"
    assert len(result.record.current_hash) == 64
    assert result.chain.verification_status == VALID
    assert result.chain.chain_length == 1
    assert result.fail_closed_decision["decision"] == "ALLOW"


def test_decision_provenance_links_multiple_decisions() -> None:
    first = record_decision_provenance([], _decision(0), approval_state="NONE")
    second = record_decision_provenance([first.record], _decision(1, "HUMAN_REVIEW", "HIGH"), approval_state="PENDING")

    assert second.record.previous_hash == first.record.current_hash
    verification = verify_decision_provenance([first.record, second.record])
    assert verification["verification_status"] == VALID
    assert verification["decision"] == "ALLOW"
    assert verification["chain_length"] == 2


def test_modified_provenance_fails_closed() -> None:
    first = record_decision_provenance([], _decision(0), approval_state="NONE")
    second = record_decision_provenance([first.record], _decision(1), approval_state="NONE")
    tampered = [first.record, replace(second.record, risk_level="HIGH")]

    verification = verify_decision_provenance(tampered)

    assert verification["verification_status"] == CHAIN_BROKEN
    assert verification["decision"] == "FAIL_CLOSED"
    assert verification["reason"] == "AUDIT_CHAIN_BROKEN"
    assert chain_is_broken(tampered) is True


def test_removed_provenance_record_fails_closed() -> None:
    first = record_decision_provenance([], _decision(0), approval_state="NONE")
    second = record_decision_provenance([first.record], _decision(1), approval_state="NONE")
    third = record_decision_provenance([first.record, second.record], _decision(2), approval_state="NONE")

    verification = verify_decision_provenance([first.record, third.record])

    assert verification["verification_status"] == CHAIN_BROKEN
    assert verification["decision"] == "FAIL_CLOSED"


def test_replayed_provenance_dicts_verify() -> None:
    first = record_decision_provenance([], _decision(0), approval_state="NONE")
    second = record_decision_provenance([first.record], _decision(1), approval_state="NONE")

    verification = verify_decision_provenance([first.record.to_dict(), second.record.to_dict()])

    assert verification["verification_status"] == VALID
    assert verification["latest_hash"] == second.record.current_hash
