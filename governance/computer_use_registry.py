from __future__ import annotations

from typing import Any

from governance.action_governance import evaluate_action_governance
from governance.browser_governance import evaluate_browser_governance
from governance.computer_use_contracts import validate_computer_use_record
from governance.computer_use_lineage import evaluate_computer_use_lineage
from governance.desktop_governance import evaluate_desktop_governance
from governance.operator_governance import evaluate_operator_governance
from governance.ui_tars_governance import evaluate_ui_tars_governance


class ComputerUseRegistry:
    def __init__(self, records: list[dict[str, Any]] | None = None):
        self._records = tuple(record for record in records or [] if isinstance(record, dict))

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        for record in self._records:
            if record.get("agent_id") == agent_id:
                return dict(record)
        return None

    def list_agents(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        for record in self._records:
            validation = validate_computer_use_record(record)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
        if not self._records:
            reasons.append("UNKNOWN_AGENT")
        clean = sorted(set(str(reason) for reason in reasons if reason))
        return {"computer_use_registry_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}


def _status_for(result: dict[str, Any], key: str) -> str:
    return str(result.get(key, "BLOCKED"))


def evaluate_computer_use_governance(
    *,
    record: dict[str, Any] | None,
    registry: ComputerUseRegistry | None = None,
    requesting_tenant_id: str = "",
    requesting_workspace_id: str = "",
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_computer_use_record(record)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("UNKNOWN_AGENT",))
    operator = evaluate_operator_governance(record)
    ui_tars = evaluate_ui_tars_governance(record)
    browser = evaluate_browser_governance(record)
    desktop = evaluate_desktop_governance(record)
    action = evaluate_action_governance(record, requesting_tenant_id=requesting_tenant_id, requesting_workspace_id=requesting_workspace_id)
    lineage = evaluate_computer_use_lineage(record)
    registry_records = registry.list_agents() if isinstance(registry, ComputerUseRegistry) else ([record] if isinstance(record, dict) else [])
    registry_summary = ComputerUseRegistry(registry_records).summary()
    for result in (operator, ui_tars, browser, desktop, action, lineage, registry_summary):
        reasons.extend(result.get("reason_codes", []))
    reason_codes = sorted(set(str(reason) for reason in reasons if reason))
    status = "GOVERNED" if not reason_codes else "BLOCKED"
    return {
        "schema": "usbay.computer_use.governance.state.v1",
        "computer_use_status": status,
        "operator_status": _status_for(operator, "operator_status"),
        "ui_tars_status": _status_for(ui_tars, "ui_tars_status"),
        "browser_status": browser["browser_status"],
        "desktop_status": desktop["desktop_status"],
        "computer_use_reason_codes": reason_codes,
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "browser_control_enabled": False,
        "mouse_control_enabled": False,
        "keyboard_control_enabled": False,
        "application_launch_enabled": False,
        "file_modification_enabled": False,
        "shell_control_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation": False,
        "auto_approval": False,
    }


def empty_computer_use_dashboard_state() -> dict[str, Any]:
    return {
        "computer_use_status": "BLOCKED",
        "operator_status": "BLOCKED",
        "ui_tars_status": "BLOCKED",
        "browser_status": "BLOCKED",
        "desktop_status": "BLOCKED",
        "computer_use_reason_codes": ["UNKNOWN_AGENT", "UNKNOWN_ACTION"],
        "fail_closed": True,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "browser_control_enabled": False,
        "mouse_control_enabled": False,
        "keyboard_control_enabled": False,
        "application_launch_enabled": False,
        "file_modification_enabled": False,
        "shell_control_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation": False,
        "auto_approval": False,
    }
