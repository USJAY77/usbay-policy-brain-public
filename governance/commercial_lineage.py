from __future__ import annotations

from typing import Any


def evaluate_commercial_lineage(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.extend(["MISSING_POLICY_BINDING", "MISSING_AUDIT_LINKAGE", "MISSING_EVIDENCE_LINKAGE", "MISSING_LINEAGE"])
    else:
        if record.get("policy_binding") is not True or not str(record.get("policy_version", "")).strip():
            reasons.append("MISSING_POLICY_BINDING")
        if not str(record.get("audit_hash", "")).strip():
            reasons.append("MISSING_AUDIT_LINKAGE")
        if not str(record.get("evidence_hash", "")).strip():
            reasons.append("MISSING_EVIDENCE_LINKAGE")
        if not str(record.get("lineage_hash", "")).strip():
            reasons.append("MISSING_LINEAGE")
        if record.get("governance_bypass") is True:
            reasons.append("COMMERCIAL_GOVERNANCE_BYPASS")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"commercial_lineage_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
