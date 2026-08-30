from __future__ import annotations

from datetime import datetime
from typing import Any

from governance.license_contracts import validate_license_record


class LicenseRegistry:
    def __init__(self, records: list[dict[str, Any]] | None = None, *, now: datetime | None = None):
        self._records = tuple(record for record in records or [] if isinstance(record, dict))
        self._now = now

    def get_license(self, license_id: str) -> dict[str, Any] | None:
        for record in self._records:
            if record.get("license_id") == license_id:
                return dict(record)
        return None

    def list_licenses(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]

    def active_licenses(self) -> list[dict[str, Any]]:
        return [
            dict(record)
            for record in self._records
            if validate_license_record(record, now=self._now).valid and record.get("license_state") == "ACTIVE"
        ]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        for record in self._records:
            validation = validate_license_record(record, now=self._now)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
        active_count = len(self.active_licenses())
        status = "VALID" if active_count and not reasons else "BLOCKED"
        return {
            "license_registry_status": status,
            "active_license_count": active_count,
            "license_reason_codes": sorted(set(reasons)) or ([] if self._records else ["MISSING_LICENSE"]),
            "read_only": True,
            "register_enabled": False,
            "update_enabled": False,
            "delete_enabled": False,
            "billing_execution_enabled": False,
            "payment_processing_enabled": False,
            "auto_renewal": False,
            "auto_upgrade": False,
            "auto_assignment": False,
        }


def evaluate_license_registry(records: list[dict[str, Any]] | None, *, now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(records, list):
        return LicenseRegistry(now=now).summary()
    return LicenseRegistry(records, now=now).summary()
