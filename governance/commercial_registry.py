from __future__ import annotations

from typing import Any

from governance.commercial_contracts import validate_commercial_record


class CommercialRegistry:
    def __init__(self, records: list[dict[str, Any]] | None = None):
        self._records = tuple(record for record in records or [] if isinstance(record, dict))

    def get_commercial_record(self, commercial_id: str) -> dict[str, Any] | None:
        for record in self._records:
            if record.get("commercial_id") == commercial_id:
                return dict(record)
        return None

    def list_commercial_records(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        for record in self._records:
            validation = validate_commercial_record(record)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
        if not self._records:
            reasons.append("UNKNOWN_COMMERCIAL_RECORD")
        clean = sorted(set(str(reason) for reason in reasons if reason))
        return {
            "commercial_registry_status": "VALID" if not clean else "BLOCKED",
            "commercial_record_count": len(self._records),
            "commercial_reason_codes": clean,
            "read_only": True,
            "billing_execution_enabled": False,
            "payment_processing_enabled": False,
            "invoice_sending_enabled": False,
            "contract_signing_enabled": False,
            "customer_activation_enabled": False,
            "subscription_activation_enabled": False,
            "renewal_execution_enabled": False,
            "pricing_modification_enabled": False,
            "connector_write_enabled": False,
            "email_sending_enabled": False,
            "deployment_enabled": False,
            "auto_remediation": False,
            "auto_approval": False,
        }


def empty_commercial_dashboard_state() -> dict[str, Any]:
    return {
        "commercial_status": "BLOCKED",
        "customer_commercial_status": "BLOCKED",
        "contract_status": "BLOCKED",
        "subscription_status": "BLOCKED",
        "billing_status": "BLOCKED",
        "invoice_status": "BLOCKED",
        "pricing_status": "BLOCKED",
        "renewal_status": "BLOCKED",
        "commercial_reason_codes": ["UNKNOWN_COMMERCIAL_RECORD"],
        "fail_closed": True,
        "read_only": True,
        "billing_execution_enabled": False,
        "payment_processing_enabled": False,
        "invoice_sending_enabled": False,
        "contract_signing_enabled": False,
        "customer_activation_enabled": False,
        "subscription_activation_enabled": False,
        "renewal_execution_enabled": False,
        "pricing_modification_enabled": False,
        "connector_write_enabled": False,
        "email_sending_enabled": False,
        "deployment_enabled": False,
        "auto_remediation": False,
        "auto_approval": False,
    }
