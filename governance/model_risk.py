from __future__ import annotations

from typing import Any


KNOWN_RISK_STATUSES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


def evaluate_model_risk(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or str(record.get("risk_status", "")) not in KNOWN_RISK_STATUSES:
        reasons.append("MODEL_RISK_UNKNOWN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"model_risk_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
