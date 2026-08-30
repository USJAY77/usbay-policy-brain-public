from __future__ import annotations

from typing import Any


def evaluate_clamav_governance(record: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(record, dict):
        reasons.append("UNKNOWN_ARTIFACT")
    else:
        if record.get("scan_engine") not in {"CLAMAV", "MULTI_ENGINE"}:
            reasons.append("UNKNOWN_SCAN_ENGINE")
        if record.get("clamav_valid") is not True:
            reasons.append("UNTRUSTED_SCAN_RESULT")
        if record.get("scan_policy") is not True:
            reasons.append("MISSING_SCAN_POLICY")
        if record.get("malware_detected") is True:
            reasons.append("MALWARE_DETECTED")
    clean = sorted(set(reasons))
    return {
        "schema": "usbay.malware.clamav.v1",
        "clamav_status": "VALID" if not clean else "BLOCKED",
        "reason_codes": clean,
        "read_only": True,
        "malware_execution_enabled": False,
        "quarantine_enabled": False,
    }
