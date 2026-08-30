from __future__ import annotations

from typing import Any


def evaluate_computer_use_lineage(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_AGENT")
    else:
        if not str(record.get("audit_hash", "")).strip():
            reasons.append("MISSING_AUDIT_LINKAGE")
        if not str(record.get("evidence_hash", "")).strip():
            reasons.append("MISSING_EVIDENCE_LINKAGE")
        if not str(record.get("lineage_hash", "")).strip():
            reasons.append("MISSING_LINEAGE")
        if record.get("policy_binding") is not True:
            reasons.append("MISSING_POLICY_BINDING")
        if record.get("governance_bypass") is True:
            reasons.append("COMPUTER_USE_GOVERNANCE_BYPASS")
    clean = sorted(set(reasons))
    return {"computer_use_lineage_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
