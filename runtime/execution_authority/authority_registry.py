from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Iterable


def registry_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthorityRecord:
    authority_id: str
    owner: str
    scopes: tuple[str, ...]
    active: bool = True

    def evidence_hash(self) -> str:
        return registry_hash(self.authority_id, self.owner, ",".join(sorted(self.scopes)), self.active)


@dataclass
class AuthorityRegistry:
    records: dict[str, AuthorityRecord] = field(default_factory=dict)

    def register(self, record: AuthorityRecord) -> AuthorityRecord:
        self.records[record.authority_id] = record
        return record

    def get(self, authority_id: str) -> AuthorityRecord | None:
        return self.records.get(authority_id)

    def revoke(self, authority_id: str) -> AuthorityRecord | None:
        record = self.records.get(authority_id)
        if record is None:
            return None
        revoked = AuthorityRecord(record.authority_id, record.owner, record.scopes, active=False)
        self.records[authority_id] = revoked
        return revoked

    def has_scope(self, authority_id: str, required_scope: str) -> bool:
        record = self.records.get(authority_id)
        return bool(record and record.active and required_scope in record.scopes)

    @classmethod
    def from_records(cls, records: Iterable[AuthorityRecord]) -> "AuthorityRegistry":
        registry = cls()
        for record in records:
            registry.register(record)
        return registry

