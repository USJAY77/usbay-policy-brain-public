from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.execution_contracts import sha256_json


PROMPT_GOVERNANCE_SCHEMA = "usbay.prompt.governance.v1"
PROMPT_GOVERNANCE_POLICY_VERSION = "usbay.pb-prompt-governance.governed-prompt.v1"
SUPPORTED_PROMPT_CLASSIFICATIONS = frozenset(
    {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "REGULATED", "HIGH_RISK", "SYSTEM"}
)
PROMPT_REASON_CODES = frozenset(
    {
        "UNKNOWN_PROMPT",
        "UNREGISTERED_PROMPT",
        "MISSING_PROMPT_OWNER",
        "MISSING_PROMPT_CLASSIFICATION",
        "MISSING_POLICY_BINDING",
        "MISSING_APPROVAL",
        "MISSING_AUDIT_LINKAGE",
        "MISSING_EVIDENCE_LINKAGE",
        "MISSING_LINEAGE",
        "PROMPT_INJECTION_RISK",
        "CROSS_TENANT_PROMPT",
        "PROMPT_NOT_GOVERNED",
        "PROMPT_VALIDATION_FAILED",
        "PROMPT_GOVERNANCE_BYPASS",
        "TOOL_EXECUTION_FORBIDDEN",
        "CONNECTOR_WRITE_FORBIDDEN",
        "MODEL_INVOCATION_FORBIDDEN",
        "AUTO_ROUTING_FORBIDDEN",
        "AUTO_REMEDIATION_FORBIDDEN",
        "AUTO_APPROVAL_FORBIDDEN",
    }
)


@dataclass(frozen=True)
class PromptGovernanceValidation:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reason_codes": list(self.reason_codes)}


def canonical_prompt_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "prompt_id": str(record.get("prompt_id", "")),
        "prompt_hash": str(record.get("prompt_hash", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "workspace_id": str(record.get("workspace_id", "")),
        "prompt_owner": str(record.get("prompt_owner", "")),
        "prompt_classification": str(record.get("prompt_classification", "")),
        "registered_prompt": record.get("registered_prompt") is True,
        "prompt_governed": record.get("prompt_governed") is True,
        "human_approval": record.get("human_approval") is True,
        "policy_binding": record.get("policy_binding") is True,
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "validation_status": str(record.get("validation_status", "")),
        "injection_status": str(record.get("injection_status", "")),
        "policy_version": str(record.get("policy_version", "")),
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_prompt_governance_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_prompt_payload(record))


def validate_prompt_record(record: dict[str, Any] | None) -> PromptGovernanceValidation:
    if not isinstance(record, dict):
        return PromptGovernanceValidation(False, "BLOCKED", ("UNKNOWN_PROMPT",))

    reasons: list[str] = []
    if record.get("schema") != PROMPT_GOVERNANCE_SCHEMA:
        reasons.append("UNKNOWN_PROMPT")
    if not str(record.get("prompt_id", "")).strip() or not str(record.get("prompt_hash", "")).strip():
        reasons.append("UNKNOWN_PROMPT")
    if record.get("registered_prompt") is not True:
        reasons.append("UNREGISTERED_PROMPT")
    if not str(record.get("prompt_owner", "")).strip():
        reasons.append("MISSING_PROMPT_OWNER")
    if str(record.get("prompt_classification", "")) not in SUPPORTED_PROMPT_CLASSIFICATIONS:
        reasons.append("MISSING_PROMPT_CLASSIFICATION")
    if record.get("policy_binding") is not True or not str(record.get("policy_version", "")).strip():
        reasons.append("MISSING_POLICY_BINDING")
    if record.get("human_approval") is not True:
        reasons.append("MISSING_APPROVAL")
    if not str(record.get("audit_hash", "")).strip():
        reasons.append("MISSING_AUDIT_LINKAGE")
    if not str(record.get("evidence_hash", "")).strip():
        reasons.append("MISSING_EVIDENCE_LINKAGE")
    if not str(record.get("lineage_hash", "")).strip():
        reasons.append("MISSING_LINEAGE")
    if record.get("prompt_governed") is not True:
        reasons.append("PROMPT_NOT_GOVERNED")
    if str(record.get("validation_status", "")) != "VALIDATED":
        reasons.append("PROMPT_VALIDATION_FAILED")
    if str(record.get("injection_status", "")) != "CLEAN":
        reasons.append("PROMPT_INJECTION_RISK")
    if record.get("tenant_id") and record.get("requesting_tenant_id") and record.get("tenant_id") != record.get("requesting_tenant_id"):
        reasons.append("CROSS_TENANT_PROMPT")
    if record.get("workspace_id") and record.get("requesting_workspace_id") and record.get("workspace_id") != record.get("requesting_workspace_id"):
        reasons.append("CROSS_TENANT_PROMPT")

    forbidden_flags = {
        "prompt_execution": "PROMPT_GOVERNANCE_BYPASS",
        "inference_execution": "PROMPT_GOVERNANCE_BYPASS",
        "deployment": "PROMPT_GOVERNANCE_BYPASS",
        "governance_bypass": "PROMPT_GOVERNANCE_BYPASS",
        "tool_execution": "TOOL_EXECUTION_FORBIDDEN",
        "connector_write": "CONNECTOR_WRITE_FORBIDDEN",
        "model_invocation": "MODEL_INVOCATION_FORBIDDEN",
        "auto_routing": "AUTO_ROUTING_FORBIDDEN",
        "auto_remediation": "AUTO_REMEDIATION_FORBIDDEN",
        "auto_approval": "AUTO_APPROVAL_FORBIDDEN",
    }
    for field, reason in forbidden_flags.items():
        if record.get(field) is True:
            reasons.append(reason)

    if not isinstance(record.get("reason_codes"), list):
        reasons.append("PROMPT_GOVERNANCE_BYPASS")
    if record.get("prompt_governance_hash") and record.get("prompt_governance_hash") != compute_prompt_governance_hash(record):
        return PromptGovernanceValidation(False, "TAMPER_DETECTED", ("PROMPT_GOVERNANCE_BYPASS",))

    clean = tuple(sorted(set(reasons)))
    return PromptGovernanceValidation(not clean, "GOVERNED" if not clean else "BLOCKED", clean)


def build_prompt_record(
    *,
    prompt_id: str,
    prompt_hash: str,
    tenant_id: str,
    workspace_id: str,
    prompt_owner: str,
    prompt_classification: str,
    registered_prompt: bool,
    prompt_governed: bool,
    human_approval: bool,
    policy_binding: bool,
    audit_hash: str,
    evidence_hash: str,
    lineage_hash: str,
    validation_status: str,
    injection_status: str,
    policy_version: str,
    prompt_execution: bool = False,
    inference_execution: bool = False,
    tool_execution: bool = False,
    connector_write: bool = False,
    model_invocation: bool = False,
    auto_routing: bool = False,
    deployment: bool = False,
    auto_remediation: bool = False,
    auto_approval: bool = False,
    governance_bypass: bool = False,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = False,
) -> dict[str, Any]:
    record = {
        "schema": PROMPT_GOVERNANCE_SCHEMA,
        "prompt_id": str(prompt_id),
        "prompt_hash": str(prompt_hash),
        "tenant_id": str(tenant_id),
        "workspace_id": str(workspace_id),
        "prompt_owner": str(prompt_owner),
        "prompt_classification": str(prompt_classification),
        "registered_prompt": bool(registered_prompt),
        "prompt_governed": bool(prompt_governed),
        "human_approval": bool(human_approval),
        "policy_binding": bool(policy_binding),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "lineage_hash": str(lineage_hash),
        "validation_status": str(validation_status),
        "injection_status": str(injection_status),
        "policy_version": str(policy_version),
        "prompt_execution": bool(prompt_execution),
        "inference_execution": bool(inference_execution),
        "tool_execution": bool(tool_execution),
        "connector_write": bool(connector_write),
        "model_invocation": bool(model_invocation),
        "auto_routing": bool(auto_routing),
        "deployment": bool(deployment),
        "auto_remediation": bool(auto_remediation),
        "auto_approval": bool(auto_approval),
        "governance_bypass": bool(governance_bypass),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "fail_closed": bool(fail_closed),
        "prompt_governance_hash": "",
    }
    record["prompt_governance_hash"] = compute_prompt_governance_hash(record)
    return record
