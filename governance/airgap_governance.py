from __future__ import annotations

from typing import Any


def evaluate_airgap_governance(state: dict[str, Any] | None) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(state, dict):
        reasons.append("AIRGAP_STATE_MALFORMED")
    else:
        if state.get("offline_mode") is not True:
            reasons.append("AIRGAP_OFFLINE_MODE_NOT_CONFIRMED")
        if state.get("mesh_mode") not in {"DISABLED", "CONTROLLED", "OFFLINE_MESH"}:
            reasons.append("AIRGAP_MESH_MODE_UNKNOWN")
        if not str(state.get("synchronization_lineage", "")).strip():
            reasons.append("AIRGAP_SYNCHRONIZATION_UNKNOWN")
        if not str(state.get("lineage_hash", "")).strip():
            reasons.append("AIRGAP_LINEAGE_BROKEN")
        if not str(state.get("evidence_continuity", "")).strip() or state.get("evidence_continuity") == "BROKEN":
            reasons.append("AIRGAP_EVIDENCE_CONTINUITY_MISSING")
    status = "READY" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.sovereign.environment.v1",
        "airgap_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status != "READY",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "synchronization_write_enabled": False,
        "auto_deploy": False,
        "auto_update": False,
        "auto_remediate": False,
    }
