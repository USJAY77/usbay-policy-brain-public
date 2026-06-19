from __future__ import annotations

from typing import Any

from governance.capability_manifest import CAPABILITY_MANIFEST


EVIDENCE_NORMALIZATION_SCHEMA = "usbay.governance.evidence_normalization.v1"
REASON_EVIDENCE_CONTROL_MISSING = "EVIDENCE_CONTROL_MISSING"


def evidence_normalization_report(
    manifest: tuple[dict[str, Any], ...] = CAPABILITY_MANIFEST,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    reasons: list[str] = []
    for capability in manifest:
        capability_id = str(capability.get("capability_id", ""))
        controls = tuple(str(control) for control in capability.get("controls", ()))
        row_reasons = [] if "evidence_linkage" in controls else [REASON_EVIDENCE_CONTROL_MISSING]
        reasons.extend(row_reasons)
        rows.append(
            {
                "capability_id": capability_id,
                "evidence_status": "VALID" if not row_reasons else "BLOCKED",
                "evidence_required": True,
                "evidence_owner": capability_id,
                "reason_codes": row_reasons,
            }
        )
    clean_reasons = sorted(set(reasons))
    return {
        "schema": EVIDENCE_NORMALIZATION_SCHEMA,
        "evidence_status": "VALID" if not clean_reasons else "BLOCKED",
        "capability_count": len(rows),
        "capabilities": rows,
        "reason_codes": clean_reasons,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }
