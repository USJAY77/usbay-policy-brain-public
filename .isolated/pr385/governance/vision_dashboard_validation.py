from __future__ import annotations

from typing import Any

from governance.capability_manifest import CAPABILITY_MANIFEST
from governance.dashboard_owner_registry import DASHBOARD_OWNER_REGISTRY
from governance.dashboard_validation import validate_dashboard_ownership
from governance.reason_code_registry import REASON_CODE_NAMESPACES
from governance.vision_consolidation import VISION_CAPABILITY_ID
from governance.vision_governance import empty_vision_dashboard_state


VISION_DASHBOARD_VALIDATION_SCHEMA = "usbay.governance.vision_dashboard_validation.v1"
REASON_VISION_DASHBOARD_OWNER_INVALID = "VISION_DASHBOARD_OWNER_INVALID"
REASON_VISION_DASHBOARD_FIELD_MISSING = "VISION_DASHBOARD_FIELD_MISSING"
REASON_VISION_DASHBOARD_REASON_CODE_INVALID = "VISION_DASHBOARD_REASON_CODE_INVALID"


def validate_vision_dashboard(
    dashboard_state: dict[str, Any] | None = None,
    dashboard_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] = DASHBOARD_OWNER_REGISTRY,
    manifest: tuple[dict[str, Any], ...] = CAPABILITY_MANIFEST,
) -> dict[str, Any]:
    state = dict(dashboard_state) if isinstance(dashboard_state, dict) else empty_vision_dashboard_state()
    dashboard_validation = validate_dashboard_ownership(records=dashboard_records, manifest=manifest)
    vision_records = [record for record in dashboard_records if record.get("capability_id") == VISION_CAPABILITY_ID]
    expected_fields = _expected_fields(manifest)
    reasons: list[str] = []
    if len(vision_records) != 1:
        reasons.append(REASON_VISION_DASHBOARD_OWNER_INVALID)
    missing_fields = sorted(field for field in expected_fields if field not in state)
    if missing_fields:
        reasons.append(REASON_VISION_DASHBOARD_FIELD_MISSING)
    allowed_reasons = set(REASON_CODE_NAMESPACES.get("vision", ()))
    vision_reasons = [str(code) for code in state.get("vision_reason_codes", [])]
    invalid_reasons = sorted(code for code in vision_reasons if code not in allowed_reasons)
    if invalid_reasons:
        reasons.append(REASON_VISION_DASHBOARD_REASON_CODE_INVALID)
    clean_reasons = sorted(set(reasons + dashboard_validation["reason_codes"]))
    return {
        "schema": VISION_DASHBOARD_VALIDATION_SCHEMA,
        "vision_dashboard_status": "VALID" if not clean_reasons else "BLOCKED",
        "dashboard_owner": str(vision_records[0].get("dashboard_owner_module", "")) if vision_records else "",
        "dashboard_fields": sorted(expected_fields),
        "missing_dashboard_fields": missing_fields,
        "invalid_reason_codes": invalid_reasons,
        "duplicate_dashboard_owner_count": 1 if REASON_VISION_DASHBOARD_OWNER_INVALID in clean_reasons else 0,
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


def _expected_fields(manifest: tuple[dict[str, Any], ...]) -> tuple[str, ...]:
    for capability in manifest:
        if capability.get("capability_id") == VISION_CAPABILITY_ID:
            return tuple(str(field) for field in capability.get("dashboard_states", ()))
    return ()
