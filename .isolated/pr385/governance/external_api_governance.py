from __future__ import annotations

from typing import Any


def evaluate_external_api_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("EXTERNAL_API_NOT_GOVERNED")
    else:
        if record.get("external_api_governed") is not True or record.get("api_invocation") is True:
            reasons.append("EXTERNAL_API_NOT_GOVERNED")
    clean = tuple(sorted(set(str(reason) for reason in reasons if reason)))
    return {
        "external_api_status": "VALID" if not clean else "BLOCKED",
        "reason_codes": list(clean),
        "read_only": True,
        "api_invocation_enabled": False,
        "network_access_enabled": False,
    }
