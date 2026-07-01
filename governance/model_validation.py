from __future__ import annotations

from typing import Any

from governance.model_contracts import validate_model_record


def evaluate_model_validation(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_model_record(record)
    if not validation.valid:
        reasons.extend(code for code in validation.reason_codes if code in {"UNKNOWN_MODEL", "MODEL_VALIDATION_FAILED", "MODEL_NOT_GOVERNED"})
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"model_validation_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
