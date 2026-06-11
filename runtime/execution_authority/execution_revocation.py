from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256

from runtime.execution_authority.authority_registry import AuthorityRegistry
from runtime.execution_authority.execution_token import ExecutionTokenLifecycle


def revocation_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RevocationRecord:
    execution_id: str
    authority_id: str | None
    token_id: str | None
    reason: str
    timestamp: str
    audit_hash: str


@dataclass
class ExecutionRevocationFramework:
    registry: AuthorityRegistry
    token_lifecycle: ExecutionTokenLifecycle
    revoked_executions: set[str] = field(default_factory=set)
    records: list[RevocationRecord] = field(default_factory=list)

    def revoke_execution(
        self,
        *,
        execution_id: str,
        reason: str,
        token_id: str | None = None,
        authority_id: str | None = None,
    ) -> RevocationRecord:
        self.revoked_executions.add(execution_id)
        if token_id:
            self.token_lifecycle.revoke(token_id)
        if authority_id:
            self.registry.revoke(authority_id)
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        record = RevocationRecord(
            execution_id=execution_id,
            authority_id=authority_id,
            token_id=token_id,
            reason=reason,
            timestamp=timestamp,
            audit_hash=revocation_hash(execution_id, authority_id, token_id, reason, timestamp),
        )
        self.records.append(record)
        return record

    def is_revoked(self, execution_id: str) -> bool:
        return execution_id in self.revoked_executions

