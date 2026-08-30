from __future__ import annotations

from typing import Any

from governance.model_contracts import validate_model_record


class ModelRegistry:
    def __init__(self, records: list[dict[str, Any]] | None = None):
        self._records = tuple(record for record in records or [] if isinstance(record, dict))

    def get_model(self, model_id: str) -> dict[str, Any] | None:
        for record in self._records:
            if record.get("model_id") == model_id:
                return dict(record)
        return None

    def list_models(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]

    def summary(self) -> dict[str, Any]:
        reasons: list[str] = []
        for record in self._records:
            validation = validate_model_record(record)
            if not validation.valid:
                reasons.extend(validation.reason_codes)
        if not self._records:
            reasons.append("UNKNOWN_MODEL")
        clean = sorted(set(str(reason) for reason in reasons if reason))
        return {
            "model_registry_status": "VALID" if not clean else "BLOCKED",
            "model_count": len(self._records),
            "model_reason_codes": clean,
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


def empty_model_dashboard_state() -> dict[str, Any]:
    return {
        "model_status": "BLOCKED",
        "model_registry_status": "BLOCKED",
        "model_validation_status": "BLOCKED",
        "model_risk_status": "BLOCKED",
        "model_lineage_status": "BLOCKED",
        "model_reason_codes": ["UNKNOWN_MODEL"],
        "fail_closed": True,
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
