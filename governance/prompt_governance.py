from __future__ import annotations

from typing import Any

from governance.prompt_contracts import validate_prompt_record
from governance.prompt_evidence import evaluate_prompt_evidence
from governance.prompt_injection_governance import evaluate_prompt_injection_governance
from governance.prompt_lineage import evaluate_prompt_lineage
from governance.prompt_policy_binding import evaluate_prompt_policy_binding
from governance.prompt_registry import PromptRegistry
from governance.prompt_validation import evaluate_prompt_validation


def evaluate_prompt_governance(
    *,
    record: dict[str, Any] | None,
    registry: PromptRegistry | None = None,
    requesting_tenant_id: str = "",
    requesting_workspace_id: str = "",
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_prompt_record(record)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("UNKNOWN_PROMPT",))
    if isinstance(record, dict):
        if requesting_tenant_id and record.get("tenant_id") != requesting_tenant_id:
            reasons.append("CROSS_TENANT_PROMPT")
        if requesting_workspace_id and record.get("workspace_id") != requesting_workspace_id:
            reasons.append("CROSS_TENANT_PROMPT")

    prompt_validation = evaluate_prompt_validation(record)
    injection = evaluate_prompt_injection_governance(record)
    lineage = evaluate_prompt_lineage(record)
    evidence = evaluate_prompt_evidence(record)
    policy = evaluate_prompt_policy_binding(record)
    registry_records = registry.list_prompts() if isinstance(registry, PromptRegistry) else ([record] if isinstance(record, dict) else [])
    registry_summary = PromptRegistry(registry_records).summary()
    for result in (prompt_validation, injection, lineage, evidence, policy, registry_summary):
        reasons.extend(result.get("reason_codes", []))

    reason_codes = sorted(set(str(reason) for reason in reasons if reason))
    status = "GOVERNED" if not reason_codes else "BLOCKED"
    return {
        "schema": "usbay.prompt.governance.state.v1",
        "prompt_status": status,
        "prompt_registry_status": registry_summary["prompt_registry_status"],
        "prompt_validation_status": prompt_validation["prompt_validation_status"],
        "prompt_injection_status": injection["prompt_injection_status"],
        "prompt_policy_binding_status": policy["prompt_policy_binding_status"],
        "prompt_lineage_status": lineage["prompt_lineage_status"],
        "prompt_reason_codes": reason_codes,
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "prompt_execution_enabled": False,
        "model_invocation_enabled": False,
        "inference_execution_enabled": False,
        "tool_execution_enabled": False,
        "connector_write_enabled": False,
        "auto_routing_enabled": False,
        "deployment_enabled": False,
        "auto_remediation": False,
        "auto_approval": False,
    }
