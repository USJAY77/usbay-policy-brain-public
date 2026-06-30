from __future__ import annotations

from typing import Any

from governance.lifecycle_contracts import validate_lifecycle_record


class LifecycleRegistry:
    def __init__(self, records: list[dict[str, Any]] | None = None):
        self._records = tuple(record for record in records or [] if isinstance(record, dict))

    def get_change(self, change_id: str) -> dict[str, Any] | None:
        for record in self._records:
            if record.get("change_id") == change_id:
                return dict(record)
        return None

    def list_changes(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        for record in self._records:
            validation = validate_lifecycle_record(record)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
        if not self._records:
            reasons.append("UNKNOWN_CHANGE")
        clean = sorted(set(str(reason) for reason in reasons if reason))
        return {
            "lifecycle_registry_status": "VALID" if not clean else "BLOCKED",
            "change_count": len(self._records),
            "lifecycle_reason_codes": clean,
            "read_only": True,
            "execution_enabled": False,
            "deployment_enabled": False,
            "runtime_modification_enabled": False,
            "policy_modification_enabled": False,
            "connector_write_enabled": False,
            "auto_release": False,
            "auto_promotion": False,
            "auto_remediation": False,
            "auto_rollback": False,
            "auto_approval": False,
        }


def empty_lifecycle_dashboard_state() -> dict[str, Any]:
    return {
        "lifecycle_status": "BLOCKED",
        "change_status": "BLOCKED",
        "release_status": "BLOCKED",
        "promotion_status": "BLOCKED",
        "runtime_status": "BLOCKED",
        "rollback_status": "BLOCKED",
        "incident_status": "BLOCKED",
        "maintenance_status": "BLOCKED",
        "lifecycle_reason_codes": ["UNKNOWN_CHANGE"],
        "fail_closed": True,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_modification_enabled": False,
        "connector_write_enabled": False,
        "auto_release": False,
        "auto_promotion": False,
        "auto_remediation": False,
        "auto_rollback": False,
        "auto_approval": False,
    }
