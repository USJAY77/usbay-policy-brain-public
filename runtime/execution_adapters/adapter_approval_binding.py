from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


REQUIRED_BINDING_FIELDS = ("decision_id", "approval_id", "policy_version", "execution_token", "authority_id")


def adapter_binding_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AdapterApprovalBinding:
    decision_id: str | None
    approval_id: str | None
    policy_version: str | None
    execution_token: str | None
    authority_id: str | None
    decision: str
    reason: str
    binding_hash: str


def validate_adapter_approval_binding(
    *,
    decision_id: str | None,
    approval_id: str | None,
    policy_version: str | None,
    execution_token: str | None,
    authority_id: str | None,
) -> AdapterApprovalBinding:
    values = {
        "decision_id": decision_id,
        "approval_id": approval_id,
        "policy_version": policy_version,
        "execution_token": execution_token,
        "authority_id": authority_id,
    }
    missing = [field for field in REQUIRED_BINDING_FIELDS if not values.get(field)]
    if missing:
        decision = "FAIL_CLOSED"
        reason = "missing_" + "_".join(missing)
    else:
        decision = "ALLOW"
        reason = "adapter_approval_binding_valid"
    return AdapterApprovalBinding(
        decision_id=decision_id,
        approval_id=approval_id,
        policy_version=policy_version,
        execution_token=execution_token,
        authority_id=authority_id,
        decision=decision,
        reason=reason,
        binding_hash=adapter_binding_hash(
            decision_id,
            approval_id,
            policy_version,
            execution_token,
            authority_id,
            decision,
            reason,
        ),
    )

