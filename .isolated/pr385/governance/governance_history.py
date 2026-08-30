from __future__ import annotations

from typing import Any

from governance.audit_registry import build_audit_registry
from governance.audit_registry_contracts import GOVERNANCE_HISTORY_SCHEMA


class GovernanceHistory:
    def __init__(self, records: list[dict[str, Any]] | None):
        self._records = tuple(record for record in records or [] if isinstance(record, dict))
        self._by_id = {str(record.get("record_id", "")): record for record in self._records}

    def get_record(self, record_id: str) -> dict[str, Any] | None:
        record = self._by_id.get(str(record_id))
        return dict(record) if isinstance(record, dict) else None

    def get_children(self, record_id: str) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records if record.get("parent_id") == record_id]

    def get_chain(self, record_id: str) -> list[dict[str, Any]]:
        chain: list[dict[str, Any]] = []
        current = self._by_id.get(str(record_id))
        visited: set[str] = set()
        while isinstance(current, dict):
            current_id = str(current.get("record_id", ""))
            if not current_id or current_id in visited:
                break
            visited.add(current_id)
            chain.append(dict(current))
            parent_id = str(current.get("parent_id", ""))
            current = self._by_id.get(parent_id)
        chain.reverse()
        return chain

    def get_history_summary(self) -> dict[str, Any]:
        registry = build_audit_registry(list(self._records))
        return {
            "schema": GOVERNANCE_HISTORY_SCHEMA,
            "governance_history_status": registry["governance_history_status"],
            "record_count": registry["audit_registry_record_count"],
            "tamper_status": registry["audit_registry_tamper_status"],
            "reason_codes": list(registry["audit_registry_reason_codes"]),
            "read_only": True,
            "mutation_enabled": False,
            "delete_enabled": False,
            "repair_enabled": False,
        }

    def get_tamper_findings(self) -> list[str]:
        registry = build_audit_registry(list(self._records))
        if registry["audit_registry_tamper_status"] != "TAMPER_DETECTED":
            return []
        return [str(code) for code in registry["audit_registry_reason_codes"] if "HASH_MISMATCH" in str(code)]
