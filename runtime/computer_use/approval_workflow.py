from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass
class ApprovalRecord:
    token: str
    action_id: str
    decision: str
    reason: str
    expires_at: datetime
    used: bool
    audit_hash: str


class ApprovalWorkflow:
    def __init__(self) -> None:
        self.queue: dict[str, ApprovalRecord] = {}

    def request(self, action_id: str, reason: str, ttl_seconds: int = 300) -> ApprovalRecord:
        token = uuid4().hex
        expires_at = _now() + timedelta(seconds=ttl_seconds)
        record = ApprovalRecord(
            token=token,
            action_id=action_id,
            decision="PENDING",
            reason=reason,
            expires_at=expires_at,
            used=False,
            audit_hash=_hash(action_id, "PENDING", reason, expires_at.isoformat()),
        )
        self.queue[token] = record
        return record

    def approve(self, token: str, reason: str) -> ApprovalRecord:
        return self._decide(token, "APPROVED", reason)

    def deny(self, token: str, reason: str) -> ApprovalRecord:
        return self._decide(token, "DENIED", reason)

    def validate(self, token: str | None, action_id: str) -> tuple[bool, str]:
        if not token or token not in self.queue:
            return False, "approval_missing"
        record = self.queue[token]
        if record.action_id != action_id:
            return False, "approval_action_mismatch"
        if record.used:
            return False, "approval_replay"
        if _now() >= record.expires_at:
            return False, "approval_expired"
        if record.decision != "APPROVED":
            return False, "approval_not_granted"
        record.used = True
        record.audit_hash = _hash(record.action_id, record.decision, record.reason, "USED")
        return True, "approval_valid"

    def _decide(self, token: str, decision: str, reason: str) -> ApprovalRecord:
        if token not in self.queue:
            raise ValueError("approval_token_missing")
        record = self.queue[token]
        record.decision = decision
        record.reason = reason
        record.audit_hash = _hash(record.action_id, decision, reason, record.expires_at.isoformat())
        return record

