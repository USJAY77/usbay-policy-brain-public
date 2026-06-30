from __future__ import annotations

from typing import Any


def evaluate_release_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("release_approval") is not True:
        reasons.append("MISSING_RELEASE_APPROVAL")
    if not isinstance(record, dict) or str(record.get("release_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_RELEASE")
    if isinstance(record, dict) and record.get("auto_release") is True:
        reasons.append("AUTO_RELEASE_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"release_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
