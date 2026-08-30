from __future__ import annotations

from typing import Any


def evaluate_incident_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("incident_record") is not True:
        reasons.append("MISSING_INCIDENT_RECORD")
    if not isinstance(record, dict) or str(record.get("incident_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_INCIDENT_ACTION")
    if isinstance(record, dict) and record.get("auto_remediation") is True:
        reasons.append("AUTO_REMEDIATION_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"incident_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
