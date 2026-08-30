from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


GENESIS = "GENESIS"


def audit_hash(previous_hash: str, decision_id: str, decision: str, policy_version: str | None) -> str:
    return sha256(f"{previous_hash}|{decision_id}|{decision}|{policy_version}".encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    decision_id: str
    decision: str
    policy_version: str | None
    previous_hash: str
    current_hash: str


class AuditChain:
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def append(self, decision_id: str, decision: str, policy_version: str | None) -> AuditEntry:
        previous = self.entries[-1].current_hash if self.entries else GENESIS
        current = audit_hash(previous, decision_id, decision, policy_version)
        entry = AuditEntry(decision_id, decision, policy_version, previous, current)
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        previous = GENESIS
        for entry in self.entries:
            if entry.previous_hash != previous:
                return False
            if entry.current_hash != audit_hash(previous, entry.decision_id, entry.decision, entry.policy_version):
                return False
            previous = entry.current_hash
        return True

