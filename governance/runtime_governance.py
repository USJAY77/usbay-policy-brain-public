from __future__ import annotations

from typing import Any


def evaluate_runtime_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("runtime_approval") is not True:
        reasons.append("MISSING_RUNTIME_APPROVAL")
    if not isinstance(record, dict) or str(record.get("runtime_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_RUNTIME_CHANGE")
    if isinstance(record, dict) and record.get("runtime_modification") is True:
        reasons.append("LIFECYCLE_GOVERNANCE_BYPASS")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"runtime_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
