from __future__ import annotations

from typing import Any

from governance.api_security_contracts import contains_sensitive_marker


def evaluate_api_input_validation(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_API")
    else:
        if record.get("input_validation_policy") is not True:
            reasons.append("MISSING_INPUT_VALIDATION_POLICY")
        if record.get("ssrf_risk") is True:
            reasons.append("SSRF_RISK_DETECTED")
        if record.get("sensitive_data_exposure") is True or contains_sensitive_marker(record):
            reasons.append("SENSITIVE_DATA_EXPOSURE")
    clean = sorted(set(reasons))
    return {
        "schema": "usbay.api.input_validation.v1",
        "api_input_validation_status": "VALID" if not clean else "BLOCKED",
        "reason_codes": clean,
        "read_only": True,
        "network_access_enabled": False,
        "sensitive_data_logging": False,
    }
