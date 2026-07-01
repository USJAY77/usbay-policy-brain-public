from __future__ import annotations

from typing import Any

from governance.prompt_contracts import validate_prompt_record


class PromptRegistry:
    def __init__(self, records: list[dict[str, Any]] | None = None):
        self._records = tuple(record for record in records or [] if isinstance(record, dict))

    def get_prompt(self, prompt_id: str) -> dict[str, Any] | None:
        for record in self._records:
            if record.get("prompt_id") == prompt_id:
                return dict(record)
        return None

    def list_prompts(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        for record in self._records:
            validation = validate_prompt_record(record)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
        if not self._records:
            reasons.append("UNKNOWN_PROMPT")
        clean = sorted(set(str(reason) for reason in reasons if reason))
        return {
            "prompt_registry_status": "VALID" if not clean else "BLOCKED",
            "prompt_count": len(self._records),
            "prompt_reason_codes": clean,
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


def empty_prompt_dashboard_state() -> dict[str, Any]:
    return {
        "prompt_status": "BLOCKED",
        "prompt_registry_status": "BLOCKED",
        "prompt_validation_status": "BLOCKED",
        "prompt_injection_status": "BLOCKED",
        "prompt_policy_binding_status": "BLOCKED",
        "prompt_lineage_status": "BLOCKED",
        "prompt_reason_codes": ["UNKNOWN_PROMPT"],
        "fail_closed": True,
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
