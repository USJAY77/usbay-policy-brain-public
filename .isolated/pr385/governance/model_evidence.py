from __future__ import annotations

from typing import Any


def evaluate_model_evidence(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.extend(["MISSING_AUDIT_LINKAGE", "MISSING_EVIDENCE_LINKAGE"])
    else:
        if not str(record.get("audit_hash", "")).strip():
            reasons.append("MISSING_AUDIT_LINKAGE")
        if not str(record.get("evidence_hash", "")).strip():
            reasons.append("MISSING_EVIDENCE_LINKAGE")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"model_evidence_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
