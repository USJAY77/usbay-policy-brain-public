from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.execution_contracts import sha256_json


COMPUTER_USE_SCHEMA = "usbay.computer_use.governance.v1"
COMPUTER_USE_POLICY_VERSION = "usbay.pb-computer-use.governed-computer-use.v1"
SUPPORTED_AGENTS = frozenset({"OPERATOR", "UI_TARS", "BROWSER_AGENT", "DESKTOP_AGENT"})
SUPPORTED_ACTIONS = frozenset({"OBSERVE", "PROPOSE", "REVIEW", "AUDIT"})
REASON_CODES = frozenset(
    {
        "UNKNOWN_AGENT",
        "UNKNOWN_ACTION",
        "UNREGISTERED_AGENT",
        "MISSING_APPROVAL",
        "MISSING_AUDIT_LINKAGE",
        "MISSING_EVIDENCE_LINKAGE",
        "MISSING_LINEAGE",
        "MISSING_POLICY_BINDING",
        "CROSS_TENANT_ACTION",
        "BROWSER_CONTROL_FORBIDDEN",
        "MOUSE_CONTROL_FORBIDDEN",
        "KEYBOARD_CONTROL_FORBIDDEN",
        "APPLICATION_CONTROL_FORBIDDEN",
        "FILE_MODIFICATION_FORBIDDEN",
        "SHELL_CONTROL_FORBIDDEN",
        "AUTO_REMEDIATION_FORBIDDEN",
        "AUTO_APPROVAL_FORBIDDEN",
        "COMPUTER_USE_GOVERNANCE_BYPASS",
    }
)
REQUIRED_FIELDS = (
    "agent_id",
    "agent_type",
    "action_id",
    "action_type",
    "tenant_id",
    "workspace_id",
    "registered_agent",
    "human_approval",
    "policy_binding",
    "audit_hash",
    "evidence_hash",
    "lineage_hash",
    "policy_version",
    "reason_codes",
    "fail_closed",
)


@dataclass(frozen=True)
class ComputerUseValidation:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reason_codes": list(self.reason_codes)}


def canonical_computer_use_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_id": str(record.get("agent_id", "")),
        "agent_type": str(record.get("agent_type", "")),
        "action_id": str(record.get("action_id", "")),
        "action_type": str(record.get("action_type", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "workspace_id": str(record.get("workspace_id", "")),
        "registered_agent": record.get("registered_agent") is True,
        "human_approval": record.get("human_approval") is True,
        "policy_binding": record.get("policy_binding") is True,
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "policy_version": str(record.get("policy_version", "")),
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_computer_use_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_computer_use_payload(record))


def validate_computer_use_record(record: dict[str, Any] | None) -> ComputerUseValidation:
    if not isinstance(record, dict):
        return ComputerUseValidation(False, "BLOCKED", ("UNKNOWN_AGENT", "UNKNOWN_ACTION"))
    reasons: list[str] = []
    if record.get("schema") != COMPUTER_USE_SCHEMA:
        reasons.append("UNKNOWN_AGENT")
    for field in REQUIRED_FIELDS:
        if record.get(field) in ("", None):
            reasons.append(f"COMPUTER_USE_{field.upper()}_MISSING")
    if not str(record.get("agent_id", "")).strip() or str(record.get("agent_type", "")) not in SUPPORTED_AGENTS:
        reasons.append("UNKNOWN_AGENT")
    if not str(record.get("action_id", "")).strip() or str(record.get("action_type", "")) not in SUPPORTED_ACTIONS:
        reasons.append("UNKNOWN_ACTION")
    if record.get("registered_agent") is not True:
        reasons.append("UNREGISTERED_AGENT")
    if record.get("human_approval") is not True:
        reasons.append("MISSING_APPROVAL")
    if record.get("policy_binding") is not True or not str(record.get("policy_version", "")).strip():
        reasons.append("MISSING_POLICY_BINDING")
    if not str(record.get("audit_hash", "")).strip():
        reasons.append("MISSING_AUDIT_LINKAGE")
    if not str(record.get("evidence_hash", "")).strip():
        reasons.append("MISSING_EVIDENCE_LINKAGE")
    if not str(record.get("lineage_hash", "")).strip():
        reasons.append("MISSING_LINEAGE")
    forbidden_flags = {
        "browser_control": "BROWSER_CONTROL_FORBIDDEN",
        "mouse_control": "MOUSE_CONTROL_FORBIDDEN",
        "keyboard_control": "KEYBOARD_CONTROL_FORBIDDEN",
        "application_control": "APPLICATION_CONTROL_FORBIDDEN",
        "file_modification": "FILE_MODIFICATION_FORBIDDEN",
        "shell_control": "SHELL_CONTROL_FORBIDDEN",
        "auto_remediation": "AUTO_REMEDIATION_FORBIDDEN",
        "auto_approval": "AUTO_APPROVAL_FORBIDDEN",
        "governance_bypass": "COMPUTER_USE_GOVERNANCE_BYPASS",
    }
    for field, reason in forbidden_flags.items():
        if record.get(field) is True:
            reasons.append(reason)
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("COMPUTER_USE_REASON_CODES_MALFORMED")
    if record.get("computer_use_hash") and record.get("computer_use_hash") != compute_computer_use_hash(record):
        return ComputerUseValidation(False, "TAMPER_DETECTED", ("COMPUTER_USE_GOVERNANCE_BYPASS",))
    status = "BLOCKED" if reasons else "GOVERNED"
    return ComputerUseValidation(not reasons, status, tuple(sorted(set(reasons))))


def build_computer_use_record(
    *,
    agent_id: str,
    agent_type: str,
    action_id: str,
    action_type: str,
    tenant_id: str,
    workspace_id: str,
    registered_agent: bool,
    human_approval: bool,
    policy_binding: bool,
    audit_hash: str,
    evidence_hash: str,
    lineage_hash: str,
    policy_version: str,
    browser_control: bool = False,
    mouse_control: bool = False,
    keyboard_control: bool = False,
    application_control: bool = False,
    file_modification: bool = False,
    shell_control: bool = False,
    auto_remediation: bool = False,
    auto_approval: bool = False,
    governance_bypass: bool = False,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = False,
) -> dict[str, Any]:
    record = {
        "schema": COMPUTER_USE_SCHEMA,
        "agent_id": str(agent_id),
        "agent_type": str(agent_type),
        "action_id": str(action_id),
        "action_type": str(action_type),
        "tenant_id": str(tenant_id),
        "workspace_id": str(workspace_id),
        "registered_agent": bool(registered_agent),
        "human_approval": bool(human_approval),
        "policy_binding": bool(policy_binding),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "lineage_hash": str(lineage_hash),
        "policy_version": str(policy_version),
        "browser_control": bool(browser_control),
        "mouse_control": bool(mouse_control),
        "keyboard_control": bool(keyboard_control),
        "application_control": bool(application_control),
        "file_modification": bool(file_modification),
        "shell_control": bool(shell_control),
        "auto_remediation": bool(auto_remediation),
        "auto_approval": bool(auto_approval),
        "governance_bypass": bool(governance_bypass),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "fail_closed": bool(fail_closed),
        "computer_use_hash": "",
    }
    record["computer_use_hash"] = compute_computer_use_hash(record)
    return record
