from __future__ import annotations

from typing import Any

from governance.capability_manifest import CAPABILITY_MANIFEST


LINEAGE_NORMALIZATION_SCHEMA = "usbay.governance.lineage_normalization.v1"
REASON_LINEAGE_CONTROL_MISSING = "LINEAGE_CONTROL_MISSING"


def lineage_normalization_report(
    manifest: tuple[dict[str, Any], ...] = CAPABILITY_MANIFEST,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    reasons: list[str] = []
    for capability in manifest:
        capability_id = str(capability.get("capability_id", ""))
        controls = tuple(str(control) for control in capability.get("controls", ()))
        row_reasons = [] if "lineage_validation" in controls else [REASON_LINEAGE_CONTROL_MISSING]
        reasons.extend(row_reasons)
        rows.append(
            {
                "capability_id": capability_id,
                "lineage_status": "VALID" if not row_reasons else "BLOCKED",
                "lineage_required": True,
                "lineage_owner": capability_id,
                "reason_codes": row_reasons,
            }
        )
    clean_reasons = sorted(set(reasons))
    return {
        "schema": LINEAGE_NORMALIZATION_SCHEMA,
        "lineage_status": "VALID" if not clean_reasons else "BLOCKED",
        "capability_count": len(rows),
        "capabilities": rows,
        "reason_codes": clean_reasons,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }
