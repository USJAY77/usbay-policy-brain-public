from __future__ import annotations

from typing import Any


def evaluate_prompt_policy_binding(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("policy_binding") is not True or not str(record.get("policy_version", "")).strip():
        reasons.append("MISSING_POLICY_BINDING")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"prompt_policy_binding_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
