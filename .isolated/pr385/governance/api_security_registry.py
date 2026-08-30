from __future__ import annotations

from typing import Any

from governance.api_access_control import evaluate_api_access_control
from governance.api_input_validation import evaluate_api_input_validation
from governance.api_inventory import evaluate_api_inventory
from governance.api_rate_limit_governance import evaluate_api_rate_limit
from governance.api_security_contracts import validate_api_security_record
from governance.api_security_lineage import evaluate_api_security_lineage


class ApiSecurityRegistry:
    def __init__(self, records: list[dict[str, Any]] | None = None):
        self._records = tuple(record for record in records or [] if isinstance(record, dict))

    def get_api(self, api_id: str) -> dict[str, Any] | None:
        for record in self._records:
            if record.get("api_id") == api_id:
                return dict(record)
        return None

    def list_apis(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        for record in self._records:
            validation = validate_api_security_record(record)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
        if not self._records:
            reasons.append("UNKNOWN_API")
        clean = sorted(set(str(reason) for reason in reasons if reason))
        return {
            "api_security_registry_status": "VALID" if not clean else "BLOCKED",
            "api_count": len(self._records),
            "reason_codes": clean,
            "read_only": True,
            "api_invocation_enabled": False,
            "network_access_enabled": False,
            "connector_write_enabled": False,
        }


def evaluate_api_security_governance(
    *,
    record: dict[str, Any] | None,
    registry: ApiSecurityRegistry | None = None,
    requesting_tenant_id: str = "",
    requesting_workspace_id: str = "",
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_api_security_record(record)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("UNKNOWN_API",))
    inventory = evaluate_api_inventory(record)
    access = evaluate_api_access_control(
        record,
        requesting_tenant_id=requesting_tenant_id,
        requesting_workspace_id=requesting_workspace_id,
    )
    rate_limit = evaluate_api_rate_limit(record)
    input_validation = evaluate_api_input_validation(record)
    lineage = evaluate_api_security_lineage(record)
    registry_records = registry.list_apis() if isinstance(registry, ApiSecurityRegistry) else ([record] if isinstance(record, dict) else [])
    registry_summary = ApiSecurityRegistry(registry_records).summary()
    for result in (inventory, access, rate_limit, input_validation, lineage, registry_summary):
        reasons.extend(result.get("reason_codes", []))
    reason_codes = sorted(set(str(reason) for reason in reasons if reason))
    status = "GOVERNED" if not reason_codes else "BLOCKED"
    return {
        "schema": "usbay.api.security.governance.v1",
        "api_security_status": status,
        "api_inventory_status": inventory["api_inventory_status"],
        "api_access_control_status": access["api_access_control_status"],
        "api_rate_limit_status": rate_limit["api_rate_limit_status"],
        "api_input_validation_status": input_validation["api_input_validation_status"],
        "api_reason_codes": reason_codes,
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "network_access_enabled": False,
        "firewall_modification_enabled": False,
        "api_invocation_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation": False,
        "auto_approval": False,
        "sensitive_data_logging": False,
    }


def empty_api_security_dashboard_state() -> dict[str, Any]:
    return {
        "api_security_status": "BLOCKED",
        "api_inventory_status": "BLOCKED",
        "api_access_control_status": "BLOCKED",
        "api_rate_limit_status": "BLOCKED",
        "api_input_validation_status": "BLOCKED",
        "api_reason_codes": ["UNKNOWN_API"],
        "fail_closed": True,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "network_access_enabled": False,
        "firewall_modification_enabled": False,
        "api_invocation_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation": False,
        "auto_approval": False,
        "sensitive_data_logging": False,
    }
