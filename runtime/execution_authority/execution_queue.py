from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256


VALID_QUEUE_STATES = {"QUEUED", "PENDING", "DENIED", "COMPLETED"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def queue_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class QueueAuditRecord:
    execution_id: str
    previous_state: str | None
    state: str
    reason: str
    timestamp: str
    audit_hash: str


@dataclass
class ExecutionQueue:
    states: dict[str, str] = field(default_factory=dict)
    audit_records: list[QueueAuditRecord] = field(default_factory=list)

    def queue(self, execution_id: str, reason: str = "queued") -> QueueAuditRecord:
        return self.transition(execution_id, "QUEUED", reason)

    def pending(self, execution_id: str, reason: str = "pending") -> QueueAuditRecord:
        return self.transition(execution_id, "PENDING", reason)

    def deny(self, execution_id: str, reason: str = "denied") -> QueueAuditRecord:
        return self.transition(execution_id, "DENIED", reason)

    def complete(self, execution_id: str, reason: str = "completed") -> QueueAuditRecord:
        return self.transition(execution_id, "COMPLETED", reason)

    def transition(self, execution_id: str, state: str, reason: str) -> QueueAuditRecord:
        if state not in VALID_QUEUE_STATES:
            state = "DENIED"
            reason = "invalid_state_fail_closed"
        previous = self.states.get(execution_id)
        self.states[execution_id] = state
        timestamp = _now()
        audit = QueueAuditRecord(
            execution_id=execution_id,
            previous_state=previous,
            state=state,
            reason=reason,
            timestamp=timestamp,
            audit_hash=queue_hash(execution_id, previous, state, reason, timestamp),
        )
        self.audit_records.append(audit)
        return audit

