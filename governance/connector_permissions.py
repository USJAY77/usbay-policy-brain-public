from __future__ import annotations

from typing import Any

from governance.connector_contracts import ALLOWED_CONNECTOR_PERMISSIONS, validate_connector_governance_record


def evaluate_connector_permissions(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_connector_governance_record(record)
    if not validation.valid:
        reasons.extend(
            code
            for code in validation.reason_codes
            if code
            in {
                "UNKNOWN_PERMISSION",
                "MISSING_APPROVAL",
                "EMAIL_SEND_FORBIDDEN",
                "CALENDAR_WRITE_FORBIDDEN",
                "REPOSITORY_WRITE_FORBIDDEN",
                "FILE_WRITE_FORBIDDEN",
                "AUTO_APPROVAL_FORBIDDEN",
            }
        )
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_PERMISSION")
    elif str(record.get("permission", "")) not in ALLOWED_CONNECTOR_PERMISSIONS:
        reasons.append("UNKNOWN_PERMISSION")
    clean = tuple(sorted(set(str(reason) for reason in reasons if reason)))
    return {
        "connector_permission_status": "VALID" if not clean else "BLOCKED",
        "reason_codes": list(clean),
        "read_only": True,
        "email_send_enabled": False,
        "calendar_write_enabled": False,
        "repository_write_enabled": False,
        "file_write_enabled": False,
        "auto_approval": False,
    }
