from __future__ import annotations

from typing import Any


def evaluate_api_security_lineage(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_API")
    else:
        if not str(record.get("audit_hash", "")).strip():
            reasons.append("MISSING_AUDIT_LINKAGE")
        if not str(record.get("evidence_hash", "")).strip():
            reasons.append("MISSING_EVIDENCE_LINKAGE")
        if not str(record.get("lineage_hash", "")).strip():
            reasons.append("MISSING_API_INVENTORY")
        if record.get("governance_bypass") is True:
            reasons.append("GOVERNANCE_BYPASS_ATTEMPT")
    clean = sorted(set(reasons))
    return {
        "schema": "usbay.api.lineage.v1",
        "api_security_lineage_status": "VALID" if not clean else "BLOCKED",
        "reason_codes": clean,
        "read_only": True,
        "auto_remediation": False,
    }
