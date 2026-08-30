from __future__ import annotations

from typing import Any


NO_DRIFT = "NO_DRIFT"
DRIFT_DETECTED = "DRIFT_DETECTED"
BLOCKED = "BLOCKED"

DRIFT_FIELDS = {
    "policy_version": "POLICY_DRIFT",
    "audit_hash": "AUDIT_DRIFT",
    "lineage_hash": "LINEAGE_DRIFT",
    "configuration_hash": "CONFIGURATION_DRIFT",
}


def detect_drift(*, baseline: dict[str, Any] | None, current: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        return {
            "drift_status": BLOCKED,
            "reason_codes": ["DRIFT_BASELINE_OR_CURRENT_MISSING"],
            "fail_closed": True,
            "auto_remediation_enabled": False,
        }
    reasons: list[str] = []
    for field, code in DRIFT_FIELDS.items():
        baseline_value = baseline.get(field)
        current_value = current.get(field)
        if baseline_value in ("", None) or current_value in ("", None):
            reasons.append(f"{code}_UNKNOWN")
        elif baseline_value != current_value:
            reasons.append(code)
    if any(reason.endswith("_UNKNOWN") for reason in reasons):
        status = BLOCKED
    elif reasons:
        status = DRIFT_DETECTED
    else:
        status = NO_DRIFT
    return {
        "drift_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status != NO_DRIFT,
        "policy_drift": "POLICY_DRIFT" in reasons,
        "audit_drift": "AUDIT_DRIFT" in reasons,
        "lineage_drift": "LINEAGE_DRIFT" in reasons,
        "configuration_drift": "CONFIGURATION_DRIFT" in reasons,
        "auto_remediation_enabled": False,
    }
