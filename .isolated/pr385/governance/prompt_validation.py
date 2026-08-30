from __future__ import annotations

from typing import Any

from governance.prompt_contracts import validate_prompt_record


def evaluate_prompt_validation(record: dict[str, Any] | None) -> dict[str, Any]:
    validation = validate_prompt_record(record)
    reasons = [
        code
        for code in validation.reason_codes
        if code in {"UNKNOWN_PROMPT", "PROMPT_VALIDATION_FAILED", "PROMPT_NOT_GOVERNED"}
    ]
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"prompt_validation_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
