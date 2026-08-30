from __future__ import annotations

from typing import Any

from governance.connector_contracts import ALLOWED_CONNECTOR_CAPABILITIES, validate_connector_governance_record


def evaluate_connector_capabilities(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_connector_governance_record(record)
    if not validation.valid:
        reasons.extend(code for code in validation.reason_codes if code in {"UNKNOWN_CAPABILITY", "CONNECTOR_EXECUTION_FORBIDDEN", "CONNECTOR_WRITE_FORBIDDEN"})
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_CAPABILITY")
    elif str(record.get("capability", "")) not in ALLOWED_CONNECTOR_CAPABILITIES:
        reasons.append("UNKNOWN_CAPABILITY")
    elif record.get("connector_execution") is True:
        reasons.append("CONNECTOR_EXECUTION_FORBIDDEN")
    elif record.get("connector_write") is True:
        reasons.append("CONNECTOR_WRITE_FORBIDDEN")
    clean = tuple(sorted(set(str(reason) for reason in reasons if reason)))
    return {
        "connector_capability_status": "VALID" if not clean else "BLOCKED",
        "reason_codes": list(clean),
        "read_only": True,
        "connector_execution_enabled": False,
        "connector_write_enabled": False,
    }
