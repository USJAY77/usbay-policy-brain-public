from __future__ import annotations

from typing import Any

from governance.aggregate_owner_registry import AGGREGATE_OWNER_REGISTRY
from governance.capability_manifest import CAPABILITY_MANIFEST
from governance.control_registry import control_ids
from governance.owner_roles import AGGREGATE_OWNER


AUDIT_NORMALIZATION_SCHEMA = "usbay.governance.audit_normalization.v1"
AUDIT_CANONICALIZATION_SCHEMA = "usbay.governance.audit_canonicalization.v1"
REASON_AUDIT_CONTROL_MISSING = "AUDIT_CONTROL_MISSING"
REASON_AUDIT_OWNER_MISSING = "AUDIT_OWNER_MISSING"
REASON_AUDIT_CONTROL_UNKNOWN = "AUDIT_CONTROL_UNKNOWN"


def audit_normalization_report(
    manifest: tuple[dict[str, Any], ...] = CAPABILITY_MANIFEST,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    reasons: list[str] = []
    for capability in manifest:
        capability_id = str(capability.get("capability_id", ""))
        controls = tuple(str(control) for control in capability.get("controls", ()))
        row_reasons = [] if "audit_linkage" in controls else [REASON_AUDIT_CONTROL_MISSING]
        reasons.extend(row_reasons)
        rows.append(
            {
                "capability_id": capability_id,
                "audit_status": "VALID" if not row_reasons else "BLOCKED",
                "audit_required": True,
                "audit_owner": capability_id,
                "reason_codes": row_reasons,
            }
        )
    clean_reasons = sorted(set(reasons))
    return {
        "schema": AUDIT_NORMALIZATION_SCHEMA,
        "audit_status": "VALID" if not clean_reasons else "BLOCKED",
        "capability_count": len(rows),
        "capabilities": rows,
        "reason_codes": clean_reasons,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }


def audit_canonicalization_report() -> dict[str, Any]:
    normalized = audit_normalization_report()
    rows = _canonical_rows(normalized, "audit_status", "audit_linkage")
    gaps = [row for row in rows if row["audit_status"] != "VALID" or row["reason_codes"]]
    return {
        "schema": AUDIT_CANONICALIZATION_SCHEMA,
        "audit_canonicalization_status": "VALID" if not gaps else "BLOCKED",
        "capabilities": rows,
        "gaps": gaps,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }


def _canonical_rows(normalized: dict[str, Any], status_key: str, control_id: str) -> list[dict[str, Any]]:
    known_controls = set(control_ids())
    aggregate_owners = {
        str(record["capability_id"]): str(record["module"])
        for record in AGGREGATE_OWNER_REGISTRY
        if record.get("owner_role") == AGGREGATE_OWNER
    }
    normalized_by_capability = {row["capability_id"]: row for row in normalized["capabilities"]}
    rows: list[dict[str, Any]] = []
    for capability in CAPABILITY_MANIFEST:
        capability_id = str(capability["capability_id"])
        reasons: list[str] = []
        controls = tuple(str(control) for control in capability.get("controls", ()))
        if capability_id not in aggregate_owners:
            reasons.append(REASON_AUDIT_OWNER_MISSING)
        if control_id not in known_controls:
            reasons.append(REASON_AUDIT_CONTROL_UNKNOWN)
        row = normalized_by_capability.get(capability_id, {})
        rows.append(
            {
                "capability": capability_id,
                "aggregate_owner": aggregate_owners.get(capability_id, ""),
                "audit_status": row.get(status_key, "BLOCKED"),
                "control_present": control_id in controls,
                "reason_codes": sorted(set(reasons + list(row.get("reason_codes", [])))),
            }
        )
    return rows
