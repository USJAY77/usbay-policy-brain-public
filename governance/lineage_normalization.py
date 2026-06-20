from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from governance.aggregate_owner_registry import AGGREGATE_OWNER_REGISTRY
from governance.capability_manifest import CAPABILITY_MANIFEST
from governance.control_registry import control_ids
from governance.owner_roles import AGGREGATE_OWNER
from scripts.verify_lineage import DEFAULT_SCHEMA, verify as verify_lineage_artifact


LINEAGE_NORMALIZATION_SCHEMA = "usbay.governance.lineage_normalization.v1"
LINEAGE_CANONICALIZATION_SCHEMA = "usbay.governance.lineage_canonicalization.v1"
REASON_LINEAGE_CONTROL_MISSING = "LINEAGE_CONTROL_MISSING"
REASON_LINEAGE_OWNER_MISSING = "LINEAGE_OWNER_MISSING"
REASON_LINEAGE_CONTROL_UNKNOWN = "LINEAGE_CONTROL_UNKNOWN"
REASON_LINEAGE_ARTIFACT_INVALID = "LINEAGE_ARTIFACT_INVALID"
LINEAGE_ARTIFACT_ENV = "USBAY_LINEAGE_ARTIFACT_PATH"
LINEAGE_SCHEMA_ENV = "USBAY_LINEAGE_SCHEMA_PATH"


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


def lineage_canonicalization_report() -> dict[str, Any]:
    normalized = lineage_normalization_report()
    artifact = lineage_artifact_validation_report()
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
            reasons.append(REASON_LINEAGE_OWNER_MISSING)
        if "lineage_validation" not in known_controls:
            reasons.append(REASON_LINEAGE_CONTROL_UNKNOWN)
        row = normalized_by_capability.get(capability_id, {})
        rows.append(
            {
                "capability": capability_id,
                "aggregate_owner": aggregate_owners.get(capability_id, ""),
                "lineage_status": row.get("lineage_status", "BLOCKED"),
                "control_present": "lineage_validation" in controls,
                "reason_codes": sorted(set(reasons + list(row.get("reason_codes", [])))),
            }
        )
    gaps = [row for row in rows if row["lineage_status"] != "VALID" or row["reason_codes"]]
    if artifact["lineage_artifact_status"] != "VALID":
        gaps.append(
            {
                "capability": "lineage_artifact",
                "aggregate_owner": "governance.lineage_normalization",
                "lineage_status": "BLOCKED",
                "control_present": True,
                "reason_codes": artifact["reason_codes"],
            }
        )
    return {
        "schema": LINEAGE_CANONICALIZATION_SCHEMA,
        "lineage_canonicalization_status": "VALID" if not gaps else "BLOCKED",
        "capabilities": rows,
        "gaps": gaps,
        "lineage_artifact": artifact,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }


def lineage_artifact_validation_report(
    *,
    schema_path: str | Path | None = None,
    lineage_path: str | Path | None = None,
) -> dict[str, Any]:
    configured_lineage = lineage_path or os.getenv(LINEAGE_ARTIFACT_ENV, "")
    configured_schema = schema_path or os.getenv(LINEAGE_SCHEMA_ENV, "")
    if not configured_lineage:
        return {
            "lineage_artifact_status": "VALID",
            "lineage_artifact_configured": False,
            "lineage_path": "",
            "schema_path": "",
            "reason_codes": [],
            "read_only": True,
            "execution_enabled": False,
        }
    schema = Path(configured_schema) if configured_schema else DEFAULT_SCHEMA
    lineage = Path(configured_lineage)
    errors = verify_lineage_artifact(schema, lineage)
    return {
        "lineage_artifact_status": "VALID" if not errors else "BLOCKED",
        "lineage_artifact_configured": True,
        "lineage_path": str(lineage),
        "schema_path": str(schema),
        "reason_codes": [] if not errors else [REASON_LINEAGE_ARTIFACT_INVALID, *errors],
        "read_only": True,
        "execution_enabled": False,
    }
