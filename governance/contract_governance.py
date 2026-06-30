from __future__ import annotations

from typing import Any


def evaluate_contract_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict) or record.get("contract_record") is not True:
        reasons.append("MISSING_CONTRACT_RECORD")
    if not isinstance(record, dict) or str(record.get("contract_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_CONTRACT_ACTION")
    if isinstance(record, dict) and record.get("contract_signing") is True:
        reasons.append("CONTRACT_SIGNING_FORBIDDEN")
    clean = sorted(set(str(reason) for reason in reasons if reason))
    return {"contract_status": "VALID" if not clean else "BLOCKED", "reason_codes": clean, "read_only": True}
