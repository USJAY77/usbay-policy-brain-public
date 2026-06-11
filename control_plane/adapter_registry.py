from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def adapter_registry_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AdapterRegistryRecord:
    adapter_name: str
    state: str
    readiness_state: str
    reason: str
    audit_hash: str


class AdapterRegistryDashboard:
    allowed_states = {"REGISTERED", "DISABLED", "BLOCKED"}

    def __init__(self) -> None:
        self._records: dict[str, AdapterRegistryRecord] = {}

    def register(self, adapter_name: str, state: str, readiness_state: str, reason: str) -> AdapterRegistryRecord:
        if state not in self.allowed_states:
            state = "BLOCKED"
            readiness_state = "FAIL_CLOSED"
            reason = "adapter_state_invalid"
        record = AdapterRegistryRecord(
            adapter_name=adapter_name,
            state=state,
            readiness_state=readiness_state,
            reason=reason,
            audit_hash=adapter_registry_hash(adapter_name, state, readiness_state, reason),
        )
        self._records[adapter_name] = record
        return record

    def dashboard(self) -> dict[str, object]:
        registered = [name for name, record in self._records.items() if record.state == "REGISTERED"]
        disabled = [name for name, record in self._records.items() if record.state == "DISABLED"]
        blocked = [name for name, record in self._records.items() if record.state == "BLOCKED"]
        return {
            "registered_adapters": registered,
            "disabled_adapters": disabled,
            "blocked_adapters": blocked,
            "readiness_state": "READY_FOR_REVIEW" if not blocked else "FAIL_CLOSED",
            "all_records_audited": all(bool(record.audit_hash) for record in self._records.values()),
        }

