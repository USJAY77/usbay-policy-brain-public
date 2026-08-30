from __future__ import annotations

from typing import Any

from governance.vision_consolidation import VISION_CAPABILITY_ID, validate_vision_consolidation
from governance.vision_dashboard_validation import validate_vision_dashboard
from governance.vision_governance import empty_vision_dashboard_state


VISION_RUNTIME_PARITY_SCHEMA = "usbay.governance.vision_runtime_parity.v1"
REASON_VISION_RUNTIME_TRUTH_DIVERGED = "VISION_RUNTIME_TRUTH_DIVERGED"
REASON_VISION_RUNTIME_STATUS_BLOCKED = "VISION_RUNTIME_STATUS_BLOCKED"


def validate_vision_runtime_parity(runtime_truth: dict[str, Any] | None = None) -> dict[str, Any]:
    consolidation = validate_vision_consolidation()
    dashboard = validate_vision_dashboard()
    runtime = dict(runtime_truth) if isinstance(runtime_truth, dict) else _default_runtime_truth()
    reasons: list[str] = []
    if runtime.get("capability_id") != VISION_CAPABILITY_ID:
        reasons.append(REASON_VISION_RUNTIME_TRUTH_DIVERGED)
    if runtime.get("runtime_status") not in {"VALID", "READY", "VERIFIED"}:
        reasons.append(REASON_VISION_RUNTIME_STATUS_BLOCKED)
    if runtime.get("dashboard_fields") != dashboard["dashboard_fields"]:
        reasons.append(REASON_VISION_RUNTIME_TRUTH_DIVERGED)
    if runtime.get("dashboard_owner") != consolidation["aggregate_owner"]:
        reasons.append(REASON_VISION_RUNTIME_TRUTH_DIVERGED)

    clean_reasons = sorted(set(reasons + consolidation["reason_codes"] + dashboard["reason_codes"]))
    return {
        "schema": VISION_RUNTIME_PARITY_SCHEMA,
        "vision_runtime_parity_status": "VALID" if not clean_reasons else "BLOCKED",
        "capability_id": VISION_CAPABILITY_ID,
        "manifest_truth": consolidation["vision_consolidation_status"],
        "dashboard_truth": dashboard["vision_dashboard_status"],
        "runtime_truth": str(runtime.get("runtime_status", "BLOCKED")),
        "reason_codes": clean_reasons,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation_enabled": False,
        "auto_approval_enabled": False,
    }


def _default_runtime_truth() -> dict[str, Any]:
    state = empty_vision_dashboard_state()
    return {
        "capability_id": VISION_CAPABILITY_ID,
        "runtime_status": "VALID",
        "dashboard_owner": "governance.vision_governance",
        "dashboard_fields": sorted(
            ["latest_observation_status", "latest_action_proposal_status", "vision_reason_codes"]
        ),
        "vision_reason_codes": list(state.get("vision_reason_codes", [])),
    }
