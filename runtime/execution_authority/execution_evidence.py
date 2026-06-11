from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def evidence_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExecutionEvidenceBinding:
    execution_id: str
    approval_id: str
    contract_id: str
    decision_id: str
    audit_chain_id: str
    policy_version: str
    evidence_hash: str
    decision: str
    reason: str


def bind_execution_evidence(
    *,
    execution_id: str | None,
    approval_id: str | None,
    contract_id: str | None,
    decision_id: str | None,
    audit_chain_id: str | None,
    policy_version: str | None,
) -> ExecutionEvidenceBinding:
    missing = [
        name
        for name, value in {
            "execution_id": execution_id,
            "approval_id": approval_id,
            "contract_id": contract_id,
            "decision_id": decision_id,
            "audit_chain_id": audit_chain_id,
            "policy_version": policy_version,
        }.items()
        if not value
    ]
    decision = "VERIFIED" if not missing else "FAIL_CLOSED"
    reason = "evidence_bound" if not missing else f"missing:{','.join(missing)}"
    digest = evidence_hash(execution_id, approval_id, contract_id, decision_id, audit_chain_id, policy_version, decision)
    return ExecutionEvidenceBinding(
        execution_id=execution_id or "missing",
        approval_id=approval_id or "missing",
        contract_id=contract_id or "missing",
        decision_id=decision_id or "missing",
        audit_chain_id=audit_chain_id or "missing",
        policy_version=policy_version or "missing",
        evidence_hash=digest,
        decision=decision,
        reason=reason,
    )

