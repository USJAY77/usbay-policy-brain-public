from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.execution_contracts import sha256_json


MODEL_GOVERNANCE_SCHEMA = "usbay.model.governance.v1"
MODEL_GOVERNANCE_POLICY_VERSION = "usbay.pb-model-governance.governed-model.v1"
SUPPORTED_MODEL_CLASSES = frozenset({"OpenAI", "Claude", "Gemini", "Llama", "DeepSeek", "UI-TARS", "Hydra Nodes", "Custom Models"})
MODEL_REASON_CODES = frozenset(
    {
        "UNKNOWN_MODEL",
        "UNREGISTERED_MODEL",
        "MISSING_MODEL_OWNER",
        "MISSING_MODEL_CLASSIFICATION",
        "MISSING_POLICY_BINDING",
        "MISSING_APPROVAL",
        "MISSING_AUDIT_LINKAGE",
        "MISSING_EVIDENCE_LINKAGE",
        "MISSING_LINEAGE",
        "CROSS_TENANT_MODEL",
        "MODEL_NOT_GOVERNED",
        "MODEL_RISK_UNKNOWN",
        "MODEL_VALIDATION_FAILED",
        "MODEL_GOVERNANCE_BYPASS",
        "AUTO_REMEDIATION_FORBIDDEN",
        "AUTO_APPROVAL_FORBIDDEN",
    }
)
REQUIRED_MODEL_FIELDS = (
    "model_id",
    "model_class",
    "tenant_id",
    "workspace_id",
    "model_owner",
    "model_classification",
    "registered_model",
    "model_governed",
    "human_approval",
    "policy_binding",
    "audit_hash",
    "evidence_hash",
    "lineage_hash",
    "risk_status",
    "validation_status",
    "policy_version",
    "reason_codes",
    "fail_closed",
)


@dataclass(frozen=True)
class ModelGovernanceValidation:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reason_codes": list(self.reason_codes)}


def canonical_model_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "model_id": str(record.get("model_id", "")),
        "model_class": str(record.get("model_class", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "workspace_id": str(record.get("workspace_id", "")),
        "model_owner": str(record.get("model_owner", "")),
        "model_classification": str(record.get("model_classification", "")),
        "registered_model": record.get("registered_model") is True,
        "model_governed": record.get("model_governed") is True,
        "human_approval": record.get("human_approval") is True,
        "policy_binding": record.get("policy_binding") is True,
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "risk_status": str(record.get("risk_status", "")),
        "validation_status": str(record.get("validation_status", "")),
        "policy_version": str(record.get("policy_version", "")),
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_model_governance_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_model_payload(record))


def validate_model_record(record: dict[str, Any] | None) -> ModelGovernanceValidation:
    if not isinstance(record, dict):
        return ModelGovernanceValidation(False, "BLOCKED", ("UNKNOWN_MODEL",))
    reasons: list[str] = []
    if record.get("schema") != MODEL_GOVERNANCE_SCHEMA:
        reasons.append("UNKNOWN_MODEL")
    for field in REQUIRED_MODEL_FIELDS:
        if record.get(field) in ("", None):
            reasons.append(f"MODEL_GOVERNANCE_{field.upper()}_MISSING")
    if not str(record.get("model_id", "")).strip() or str(record.get("model_class", "")) not in SUPPORTED_MODEL_CLASSES:
        reasons.append("UNKNOWN_MODEL")
    if record.get("registered_model") is not True:
        reasons.append("UNREGISTERED_MODEL")
    if not str(record.get("model_owner", "")).strip():
        reasons.append("MISSING_MODEL_OWNER")
    if not str(record.get("model_classification", "")).strip():
        reasons.append("MISSING_MODEL_CLASSIFICATION")
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
    if record.get("model_governed") is not True:
        reasons.append("MODEL_NOT_GOVERNED")
    if str(record.get("risk_status", "")) not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        reasons.append("MODEL_RISK_UNKNOWN")
    if str(record.get("validation_status", "")) != "VALIDATED":
        reasons.append("MODEL_VALIDATION_FAILED")
    if record.get("tenant_id") and record.get("requesting_tenant_id") and record.get("tenant_id") != record.get("requesting_tenant_id"):
        reasons.append("CROSS_TENANT_MODEL")
    forbidden_flags = {
        "model_execution": "MODEL_GOVERNANCE_BYPASS",
        "model_invocation": "MODEL_GOVERNANCE_BYPASS",
        "prompt_execution": "MODEL_GOVERNANCE_BYPASS",
        "inference_execution": "MODEL_GOVERNANCE_BYPASS",
        "auto_selection": "MODEL_GOVERNANCE_BYPASS",
        "auto_routing": "MODEL_GOVERNANCE_BYPASS",
        "deployment": "MODEL_GOVERNANCE_BYPASS",
        "auto_remediation": "AUTO_REMEDIATION_FORBIDDEN",
        "auto_approval": "AUTO_APPROVAL_FORBIDDEN",
        "governance_bypass": "MODEL_GOVERNANCE_BYPASS",
    }
    for field, reason in forbidden_flags.items():
        if record.get(field) is True:
            reasons.append(reason)
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("MODEL_GOVERNANCE_REASON_CODES_MALFORMED")
    if record.get("model_governance_hash") and record.get("model_governance_hash") != compute_model_governance_hash(record):
        return ModelGovernanceValidation(False, "TAMPER_DETECTED", ("MODEL_GOVERNANCE_BYPASS",))
    status = "BLOCKED" if reasons else "GOVERNED"
    return ModelGovernanceValidation(not reasons, status, tuple(sorted(set(reasons))))


def build_model_record(
    *,
    model_id: str,
    model_class: str,
    tenant_id: str,
    workspace_id: str,
    model_owner: str,
    model_classification: str,
    registered_model: bool,
    model_governed: bool,
    human_approval: bool,
    policy_binding: bool,
    audit_hash: str,
    evidence_hash: str,
    lineage_hash: str,
    risk_status: str,
    validation_status: str,
    policy_version: str,
    model_execution: bool = False,
    model_invocation: bool = False,
    prompt_execution: bool = False,
    inference_execution: bool = False,
    auto_selection: bool = False,
    auto_routing: bool = False,
    deployment: bool = False,
    auto_remediation: bool = False,
    auto_approval: bool = False,
    governance_bypass: bool = False,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = False,
) -> dict[str, Any]:
    record = {
        "schema": MODEL_GOVERNANCE_SCHEMA,
        "model_id": str(model_id),
        "model_class": str(model_class),
        "tenant_id": str(tenant_id),
        "workspace_id": str(workspace_id),
        "model_owner": str(model_owner),
        "model_classification": str(model_classification),
        "registered_model": bool(registered_model),
        "model_governed": bool(model_governed),
        "human_approval": bool(human_approval),
        "policy_binding": bool(policy_binding),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "lineage_hash": str(lineage_hash),
        "risk_status": str(risk_status),
        "validation_status": str(validation_status),
        "policy_version": str(policy_version),
        "model_execution": bool(model_execution),
        "model_invocation": bool(model_invocation),
        "prompt_execution": bool(prompt_execution),
        "inference_execution": bool(inference_execution),
        "auto_selection": bool(auto_selection),
        "auto_routing": bool(auto_routing),
        "deployment": bool(deployment),
        "auto_remediation": bool(auto_remediation),
        "auto_approval": bool(auto_approval),
        "governance_bypass": bool(governance_bypass),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "fail_closed": bool(fail_closed),
        "model_governance_hash": "",
    }
    record["model_governance_hash"] = compute_model_governance_hash(record)
    return record
