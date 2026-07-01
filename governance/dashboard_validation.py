from __future__ import annotations

from collections import defaultdict
from typing import Any

from governance.capability_manifest import CAPABILITY_MANIFEST
from governance.dashboard_owner_registry import DASHBOARD_OWNER_REGISTRY
from governance.owner_roles import AGGREGATE_OWNER, CONTRACT_OWNER, DEPRECATED_PROVIDER, PROVIDER


DASHBOARD_VALIDATION_SCHEMA = "usbay.governance.dashboard_validation.v1"
REASON_DUPLICATE_DASHBOARD_OWNER = "DUPLICATE_DASHBOARD_OWNER"
REASON_MISSING_DASHBOARD_OWNER = "MISSING_DASHBOARD_OWNER"
REASON_PROVIDER_DASHBOARD_TRUTH = "PROVIDER_DASHBOARD_TRUTH"
REASON_DASHBOARD_FIELD_CONFLICT = "DASHBOARD_FIELD_CONFLICT"
REASON_UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
REASON_MISSING_DASHBOARD_STATE = "MISSING_DASHBOARD_STATE"
REASON_INVALID_DASHBOARD_OWNER_ROLE = "INVALID_DASHBOARD_OWNER_ROLE"


def _manifest_by_capability(manifest: tuple[dict[str, Any], ...]) -> dict[str, dict[str, Any]]:
    return {str(capability.get("capability_id", "")): dict(capability) for capability in manifest if capability.get("capability_id")}


def _dashboard_fields(record: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(field) for field in record.get("dashboard_fields", ()) if field)


def validate_dashboard_ownership(
    records: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None,
    manifest: tuple[dict[str, Any], ...] = CAPABILITY_MANIFEST,
) -> dict[str, Any]:
    dashboard_records = tuple(dict(record) for record in (records if records is not None else DASHBOARD_OWNER_REGISTRY))
    manifest_by_id = _manifest_by_capability(manifest)
    manifest_ids = tuple(manifest_by_id)
    by_capability: dict[str, list[dict[str, Any]]] = defaultdict(list)
    field_owners: dict[str, list[str]] = defaultdict(list)
    reasons: list[str] = []

    for record in dashboard_records:
        capability_id = str(record.get("capability_id", ""))
        owner_role = str(record.get("owner_role", ""))
        fields = _dashboard_fields(record)
        if capability_id not in manifest_by_id:
            reasons.append(REASON_UNKNOWN_CAPABILITY)
        if owner_role in {PROVIDER, DEPRECATED_PROVIDER}:
            reasons.append(REASON_PROVIDER_DASHBOARD_TRUTH)
        elif owner_role != AGGREGATE_OWNER:
            reasons.append(REASON_INVALID_DASHBOARD_OWNER_ROLE)
        if not fields:
            reasons.append(REASON_MISSING_DASHBOARD_STATE)
        by_capability[capability_id].append(record)
        for field in fields:
            field_owners[field].append(capability_id)

    conflict_count = 0
    missing_owner_count = 0
    capability_results: list[dict[str, Any]] = []

    for capability_id in manifest_ids:
        records_for_capability = by_capability.get(capability_id, [])
        capability_reasons: list[str] = []
        if len(records_for_capability) == 0:
            missing_owner_count += 1
            capability_reasons.append(REASON_MISSING_DASHBOARD_OWNER)
        if len(records_for_capability) > 1:
            conflict_count += len(records_for_capability) - 1
            capability_reasons.append(REASON_DUPLICATE_DASHBOARD_OWNER)

        expected_fields = tuple(str(field) for field in manifest_by_id[capability_id].get("dashboard_states", ()) if field)
        emitted_fields = tuple(field for record in records_for_capability for field in _dashboard_fields(record))
        if not expected_fields:
            capability_reasons.append(REASON_MISSING_DASHBOARD_STATE)
        if records_for_capability and not emitted_fields:
            capability_reasons.append(REASON_MISSING_DASHBOARD_STATE)

        reasons.extend(capability_reasons)
        capability_results.append(
            {
                "capability_id": capability_id,
                "dashboard_owner_count": len(records_for_capability),
                "dashboard_fields": sorted(set(emitted_fields)),
                "expected_dashboard_fields": sorted(set(expected_fields)),
                "status": "VALID" if not capability_reasons else "BLOCKED",
                "reason_codes": sorted(set(capability_reasons)),
            }
        )

    conflicting_fields = sorted(field for field, owners in field_owners.items() if len(set(owners)) > 1)
    if conflicting_fields:
        conflict_count += len(conflicting_fields)
        reasons.append(REASON_DASHBOARD_FIELD_CONFLICT)

    clean_reasons = sorted(set(reason for reason in reasons if reason))
    status = "VALID" if not clean_reasons else "BLOCKED"
    return {
        "schema": DASHBOARD_VALIDATION_SCHEMA,
        "valid": status == "VALID",
        "dashboard_ownership_status": status,
        "dashboard_conflict_count": conflict_count,
        "missing_dashboard_owner_count": missing_owner_count,
        "dashboard_owner_count": len(dashboard_records),
        "capability_count": len(manifest_ids),
        "conflicting_dashboard_fields": conflicting_fields,
        "capability_results": capability_results,
        "reason_codes": clean_reasons,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "owner_role_execution_enabled": False,
        "contract_owner_role": CONTRACT_OWNER,
    }
