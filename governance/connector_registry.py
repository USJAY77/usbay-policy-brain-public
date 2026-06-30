from __future__ import annotations

from typing import Any

from governance.connector_contracts import ALLOWED_CONNECTOR_TYPES, CONNECTOR_POLICY_VERSION, CONNECTOR_REGISTRY_SCHEMA, validate_connector_governance_record


def default_connector_entry(connector_type: str, *, last_checked_at: str = "") -> dict[str, Any]:
    return {
        "connector_type": str(connector_type),
        "enabled": False,
        "read_only": True,
        "write_blocked": True,
        "requires_human_approval": True,
        "audit_required": True,
        "evidence_required": True,
        "last_checked_at": str(last_checked_at),
        "health_status": "BLOCKED",
        "reason_codes": ["CONNECTOR_DISABLED_BY_DEFAULT"],
    }


def build_connector_registry(*, last_checked_at: str = "", overrides: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    entries = {connector_type: default_connector_entry(connector_type, last_checked_at=last_checked_at) for connector_type in sorted(ALLOWED_CONNECTOR_TYPES)}
    if isinstance(overrides, dict):
        for connector_type, override in overrides.items():
            if connector_type in entries and isinstance(override, dict):
                entries[connector_type] = entries[connector_type] | override
    return {
        "schema": CONNECTOR_REGISTRY_SCHEMA,
        "policy_version": CONNECTOR_POLICY_VERSION,
        "connector_registry": entries,
        "connector_count": len(entries),
        "enabled_read_only_connectors": sorted(
            connector_type for connector_type, entry in entries.items() if entry.get("enabled") is True and entry.get("read_only") is True
        ),
        "blocked_write_actions": True,
        "connector_health": {connector_type: entry["health_status"] for connector_type, entry in entries.items()},
        "connector_audit_status": {connector_type: "REQUIRED" if entry["audit_required"] else "BLOCKED" for connector_type, entry in entries.items()},
        "connector_evidence_status": {connector_type: "REQUIRED" if entry["evidence_required"] else "BLOCKED" for connector_type, entry in entries.items()},
        "reason_codes": sorted({code for entry in entries.values() for code in entry.get("reason_codes", [])}),
        "auto_connected": False,
        "auto_synced": False,
        "auto_authorized": False,
        "auto_sent": False,
        "auto_merged": False,
        "auto_deployed": False,
        "write_enabled": False,
        "secret_access_enabled": False,
    }


def connector_available(registry: dict[str, Any] | None, connector_type: str) -> tuple[bool, tuple[str, ...]]:
    if not isinstance(registry, dict):
        return False, ("CONNECTOR_REGISTRY_MISSING",)
    entries = registry.get("connector_registry", {})
    if not isinstance(entries, dict):
        return False, ("CONNECTOR_REGISTRY_MALFORMED",)
    entry = entries.get(connector_type)
    if not isinstance(entry, dict):
        return False, (f"CONNECTOR_UNKNOWN:{connector_type or 'MISSING'}",)
    reasons: list[str] = []
    if entry.get("enabled") is not True:
        reasons.append(f"CONNECTOR_DISABLED:{connector_type}")
    if entry.get("read_only") is not True or entry.get("write_blocked") is not True:
        reasons.append(f"CONNECTOR_READ_ONLY_GUARD_INVALID:{connector_type}")
    if entry.get("health_status") != "HEALTHY":
        reasons.append(f"CONNECTOR_UNHEALTHY:{connector_type}")
    if entry.get("audit_required") is not True:
        reasons.append(f"CONNECTOR_AUDIT_NOT_REQUIRED_INVALID:{connector_type}")
    if entry.get("evidence_required") is not True:
        reasons.append(f"CONNECTOR_EVIDENCE_NOT_REQUIRED_INVALID:{connector_type}")
    return not reasons, tuple(sorted(set(reasons)))


def empty_connector_dashboard_state() -> dict[str, Any]:
    return build_connector_registry()


class GovernedConnectorRegistry:
    def __init__(self, records: list[dict[str, Any]] | None = None):
        self._records = tuple(record for record in records or [] if isinstance(record, dict))

    def get_connector(self, connector_id: str) -> dict[str, Any] | None:
        for record in self._records:
            if record.get("connector_id") == connector_id:
                return dict(record)
        return None

    def list_connectors(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        for record in self._records:
            validation = validate_connector_governance_record(record)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
        if not self._records:
            reasons.append("UNKNOWN_CONNECTOR")
        clean = sorted(set(str(reason) for reason in reasons if reason))
        return {
            "connector_registry_status": "VALID" if not clean else "BLOCKED",
            "connector_count": len(self._records),
            "connector_reason_codes": clean,
            "read_only": True,
            "connector_execution_enabled": False,
            "connector_write_enabled": False,
            "api_invocation_enabled": False,
            "email_send_enabled": False,
            "calendar_write_enabled": False,
            "repository_write_enabled": False,
            "file_write_enabled": False,
            "auto_remediation": False,
            "auto_approval": False,
        }


def empty_governed_connector_dashboard_state() -> dict[str, Any]:
    return {
        "connector_status": "BLOCKED",
        "connector_registry_status": "BLOCKED",
        "connector_capability_status": "BLOCKED",
        "connector_permission_status": "BLOCKED",
        "external_api_status": "BLOCKED",
        "connector_reason_codes": ["UNKNOWN_CONNECTOR"],
        "fail_closed": True,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "connector_execution_enabled": False,
        "connector_write_enabled": False,
        "api_invocation_enabled": False,
        "email_send_enabled": False,
        "calendar_write_enabled": False,
        "repository_write_enabled": False,
        "file_write_enabled": False,
        "auto_remediation": False,
        "auto_approval": False,
    }
