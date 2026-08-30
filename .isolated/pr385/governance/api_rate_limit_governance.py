from __future__ import annotations

from typing import Any


def evaluate_api_rate_limit(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_API")
    elif record.get("rate_limit_policy") is not True:
        reasons.append("MISSING_RATE_LIMIT_POLICY")
    clean = sorted(set(reasons))
    return {
        "schema": "usbay.api.rate_limit.v1",
        "api_rate_limit_status": "VALID" if not clean else "BLOCKED",
        "reason_codes": clean,
        "read_only": True,
        "firewall_modification_enabled": False,
        "auto_remediation": False,
    }
