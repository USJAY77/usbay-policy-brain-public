from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from runtime.computer_use.audit_chain import (
    CHAIN_BROKEN,
    VALID,
    AuditChainOutput,
    DecisionAuditRecord,
    append_decision_record,
    audit_chain_output,
    fail_closed_decision_for_chain,
    verify_chain,
)
from runtime.computer_use.decision_engine import ComputerUseExecutionDecision


@dataclass(frozen=True)
class DecisionProvenanceResult:
    record: DecisionAuditRecord
    chain: AuditChainOutput
    fail_closed_decision: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "record": self.record.to_dict(),
            "chain": self.chain.to_dict(),
            "fail_closed_decision": dict(self.fail_closed_decision),
        }


def record_decision_provenance(
    records: Iterable[DecisionAuditRecord | dict[str, Any]],
    decision: ComputerUseExecutionDecision | dict[str, Any],
    *,
    approval_state: str,
) -> DecisionProvenanceResult:
    existing_records = list(records)
    decision_payload = decision.to_dict() if isinstance(decision, ComputerUseExecutionDecision) else dict(decision)
    record = append_decision_record(
        existing_records,
        decision_id=str(decision_payload["decision_id"]),
        timestamp=str(decision_payload["timestamp"]),
        decision=str(decision_payload["decision"]),
        reason=str(decision_payload["reason"]),
        risk_level=str(decision_payload["risk_level"]),
        policy_version=str(decision_payload["policy_version"]),
        approval_state=approval_state,
    )
    updated_records = [*existing_records, record]
    chain = audit_chain_output(updated_records)
    return DecisionProvenanceResult(
        record=record,
        chain=chain,
        fail_closed_decision=fail_closed_decision_for_chain(updated_records),
    )


def verify_decision_provenance(records: Iterable[DecisionAuditRecord | dict[str, Any]]) -> dict[str, Any]:
    status = verify_chain(records)
    chain = audit_chain_output(records)
    return {
        "verification_status": status,
        "decision": "ALLOW" if status == VALID else "FAIL_CLOSED",
        "reason": "AUDIT_CHAIN_VALID" if status == VALID else "AUDIT_CHAIN_BROKEN",
        "audit_chain_id": chain.audit_chain_id,
        "chain_length": chain.chain_length,
        "genesis_hash": chain.genesis_hash,
        "latest_hash": chain.latest_hash,
    }


def chain_is_broken(records: Iterable[DecisionAuditRecord | dict[str, Any]]) -> bool:
    return verify_chain(records) == CHAIN_BROKEN
