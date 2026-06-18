from __future__ import annotations

from typing import Any


def evaluate_prompt_injection_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or str(record.get("injection_status", "")) != "CLEAN":
        reasons.append("PROMPT_INJECTION_RISK")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"prompt_injection_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
