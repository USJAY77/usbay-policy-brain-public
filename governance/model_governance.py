from __future__ import annotations

from typing import Any

from governance.model_contracts import validate_model_record
from governance.model_evidence import evaluate_model_evidence
from governance.model_lineage import evaluate_model_lineage
from governance.model_policy_binding import evaluate_model_policy_binding
from governance.model_registry import ModelRegistry
from governance.model_risk import evaluate_model_risk
from governance.model_validation import evaluate_model_validation


def evaluate_model_governance(
    *,
    record: dict[str, Any] | None,
    registry: ModelRegistry | None = None,
    requesting_tenant_id: str = "",
    requesting_workspace_id: str = "",
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_model_record(record)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("UNKNOWN_MODEL",))
    if isinstance(record, dict):
        if requesting_tenant_id and record.get("tenant_id") != requesting_tenant_id:
            reasons.append("CROSS_TENANT_MODEL")
        if requesting_workspace_id and record.get("workspace_id") != requesting_workspace_id:
            reasons.append("CROSS_TENANT_MODEL")
    model_validation = evaluate_model_validation(record)
    risk = evaluate_model_risk(record)
    lineage = evaluate_model_lineage(record)
    evidence = evaluate_model_evidence(record)
    policy = evaluate_model_policy_binding(record)
    registry_records = registry.list_models() if isinstance(registry, ModelRegistry) else ([record] if isinstance(record, dict) else [])
    registry_summary = ModelRegistry(registry_records).summary()
    for result in (model_validation, risk, lineage, evidence, policy, registry_summary):
        reasons.extend(result.get("reason_codes", []))
    reason_codes = sorted(set(str(reason) for reason in reasons if reason))
    status = "GOVERNED" if not reason_codes else "BLOCKED"
    return {
        "schema": "usbay.model.governance.state.v1",
        "model_status": status,
        "model_registry_status": registry_summary["model_registry_status"],
        "model_validation_status": model_validation["model_validation_status"],
        "model_risk_status": risk["model_risk_status"],
        "model_lineage_status": lineage["model_lineage_status"],
        "model_reason_codes": reason_codes,
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "model_execution_enabled": False,
        "model_invocation_enabled": False,
        "prompt_execution_enabled": False,
        "inference_execution_enabled": False,
        "auto_selection_enabled": False,
        "auto_routing_enabled": False,
        "deployment_enabled": False,
        "auto_remediation": False,
        "auto_approval": False,
    }
