from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4


def _now() -> datetime:
    return datetime.now(timezone.utc)


def token_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass
class ExecutionToken:
    token_id: str
    execution_id: str
    issued_to: str
    expires_at: datetime
    revoked: bool
    used: bool
    audit_hash: str


class ExecutionTokenLifecycle:
    def __init__(self) -> None:
        self.tokens: dict[str, ExecutionToken] = {}

    def issue(self, execution_id: str, issued_to: str, ttl_seconds: int = 300) -> ExecutionToken:
        token_id = uuid4().hex
        expires_at = _now() + timedelta(seconds=ttl_seconds)
        token = ExecutionToken(
            token_id=token_id,
            execution_id=execution_id,
            issued_to=issued_to,
            expires_at=expires_at,
            revoked=False,
            used=False,
            audit_hash=token_hash(token_id, execution_id, issued_to, expires_at.isoformat()),
        )
        self.tokens[token_id] = token
        return token

    def revoke(self, token_id: str) -> bool:
        token = self.tokens.get(token_id)
        if token is None:
            return False
        token.revoked = True
        token.audit_hash = token_hash(token.token_id, token.execution_id, "REVOKED")
        return True

    def validate(self, token_id: str | None, execution_id: str) -> tuple[bool, str]:
        if not token_id or token_id not in self.tokens:
            return False, "token_missing"
        token = self.tokens[token_id]
        if token.execution_id != execution_id:
            return False, "token_execution_mismatch"
        if token.revoked:
            return False, "token_revoked"
        if token.used:
            return False, "token_replay"
        if _now() >= token.expires_at:
            return False, "token_expired"
        token.used = True
        token.audit_hash = token_hash(token.token_id, token.execution_id, "USED")
        return True, "token_valid"

