from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from runtime.execution_authority.authority_registry import AuthorityRegistry


def authority_decision_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExecutionAuthorityDecision:
    execution_id: str
    authority_id: str | None
    decision: str
    reason: str
    owner: str | None
    required_scope: str
    audit_hash: str


class ExecutionAuthority:
    def __init__(self, registry: AuthorityRegistry) -> None:
        self.registry = registry

    def validate(
        self,
        *,
        execution_id: str,
        authority_id: str | None,
        required_scope: str,
        policy_version: str | None,
    ) -> ExecutionAuthorityDecision:
        if not execution_id:
            return self._decision(execution_id, authority_id, "FAIL_CLOSED", "execution_id_missing", None, required_scope)
        if not policy_version:
            return self._decision(execution_id, authority_id, "FAIL_CLOSED", "policy_version_missing", None, required_scope)
        if not authority_id:
            return self._decision(execution_id, authority_id, "FAIL_CLOSED", "authority_missing", None, required_scope)
        record = self.registry.get(authority_id)
        if record is None:
            return self._decision(execution_id, authority_id, "FAIL_CLOSED", "authority_unknown", None, required_scope)
        if not record.active:
            return self._decision(execution_id, authority_id, "BLOCK", "authority_revoked", record.owner, required_scope)
        if required_scope not in record.scopes:
            return self._decision(execution_id, authority_id, "BLOCK", "scope_not_authorized", record.owner, required_scope)
        return self._decision(execution_id, authority_id, "ALLOW", "authority_valid", record.owner, required_scope)

    def _decision(
        self,
        execution_id: str,
        authority_id: str | None,
        decision: str,
        reason: str,
        owner: str | None,
        required_scope: str,
    ) -> ExecutionAuthorityDecision:
        audit_hash = authority_decision_hash(execution_id, authority_id, decision, reason, owner, required_scope)
        return ExecutionAuthorityDecision(
            execution_id=execution_id,
            authority_id=authority_id,
            decision=decision,
            reason=reason,
            owner=owner,
            required_scope=required_scope,
            audit_hash=audit_hash,
        )

