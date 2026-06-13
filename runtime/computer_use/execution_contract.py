from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


SUPPORTED_ACTIONS = {"read_screen", "wait", "scroll", "click", "type", "open_url", "stop"}


def contract_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExecutionContract:
    contract_id: str
    decision_id: str
    audit_hash: str
    policy_version: str
    action_type: str
    target: str
    approval_token_hash: str | None
    status: str
    current_hash: str


def create_contract(
    *,
    decision_id: str | None,
    audit_hash_value: str | None,
    policy_version: str | None,
    action_type: str | None,
    target: str | None,
    status: str,
    approval_token: str | None = None,
) -> ExecutionContract:
    if not decision_id or not audit_hash_value or not policy_version or not action_type or not target:
        status = "FAIL_CLOSED"
    elif action_type not in SUPPORTED_ACTIONS:
        status = "BLOCK"
    approval_token_hash = contract_hash(approval_token) if approval_token else None
    contract_id = contract_hash(decision_id, audit_hash_value, policy_version, action_type, target)[:24]
    current = contract_hash(contract_id, decision_id, audit_hash_value, policy_version, action_type, target, status)
    return ExecutionContract(
        contract_id=contract_id,
        decision_id=decision_id or "missing",
        audit_hash=audit_hash_value or "missing",
        policy_version=policy_version or "missing",
        action_type=action_type or "missing",
        target=target or "missing",
        approval_token_hash=approval_token_hash,
        status=status,
        current_hash=current,
    )

