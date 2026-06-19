from __future__ import annotations

from collections import defaultdict
from typing import Any

from governance.aggregate_owner_registry import AGGREGATE_OWNER_REGISTRY
from governance.capability_manifest import CAPABILITY_MANIFEST
from governance.owner_roles import AGGREGATE_OWNER, CONTRACT_OWNER, DEPRECATED_PROVIDER, OWNER_ROLES, PROVIDER


OWNER_VALIDATION_SCHEMA = "usbay.governance.owner_validation.v1"
REASON_DUPLICATE_AGGREGATE_OWNER = "DUPLICATE_AGGREGATE_OWNER"
REASON_MISSING_AGGREGATE_OWNER = "MISSING_AGGREGATE_OWNER"
REASON_MISSING_CONTRACT_OWNER = "MISSING_CONTRACT_OWNER"
REASON_UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
REASON_INVALID_OWNER_ROLE = "INVALID_OWNER_ROLE"
REASON_MISSING_OWNER_MODULE = "MISSING_OWNER_MODULE"


def _manifest_capability_ids(manifest: tuple[dict[str, Any], ...]) -> tuple[str, ...]:
    return tuple(str(capability.get("capability_id", "")) for capability in manifest if capability.get("capability_id"))


def validate_owner_registry(
    records: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None,
    manifest: tuple[dict[str, Any], ...] = CAPABILITY_MANIFEST,
) -> dict[str, Any]:
    owner_records = tuple(dict(record) for record in (records if records is not None else AGGREGATE_OWNER_REGISTRY))
    manifest_ids = _manifest_capability_ids(manifest)
    known_capabilities = set(manifest_ids)
    by_capability: dict[str, list[dict[str, Any]]] = defaultdict(list)
    reasons: list[str] = []

    for record in owner_records:
        capability_id = str(record.get("capability_id", ""))
        module = str(record.get("module", ""))
        owner_role = str(record.get("owner_role", ""))
        if capability_id not in known_capabilities:
            reasons.append(REASON_UNKNOWN_CAPABILITY)
        if owner_role not in OWNER_ROLES:
            reasons.append(REASON_INVALID_OWNER_ROLE)
        if not module.strip():
            reasons.append(REASON_MISSING_OWNER_MODULE)
        by_capability[capability_id].append(record)

    conflict_count = 0
    missing_aggregate_count = 0
    missing_contract_count = 0
    capability_results: list[dict[str, Any]] = []

    for capability_id in manifest_ids:
        records_for_capability = by_capability.get(capability_id, [])
        aggregate_owners = [record for record in records_for_capability if record.get("owner_role") == AGGREGATE_OWNER]
        contract_owners = [record for record in records_for_capability if record.get("owner_role") == CONTRACT_OWNER]
        capability_reasons: list[str] = []
        if len(aggregate_owners) > 1:
            conflict_count += len(aggregate_owners) - 1
            capability_reasons.append(REASON_DUPLICATE_AGGREGATE_OWNER)
        if len(aggregate_owners) == 0:
            missing_aggregate_count += 1
            capability_reasons.append(REASON_MISSING_AGGREGATE_OWNER)
        if len(contract_owners) == 0:
            missing_contract_count += 1
            capability_reasons.append(REASON_MISSING_CONTRACT_OWNER)
        reasons.extend(capability_reasons)
        capability_results.append(
            {
                "capability_id": capability_id,
                "aggregate_owner_count": len(aggregate_owners),
                "contract_owner_count": len(contract_owners),
                "provider_count": len([record for record in records_for_capability if record.get("owner_role") == PROVIDER]),
                "deprecated_provider_count": len(
                    [record for record in records_for_capability if record.get("owner_role") == DEPRECATED_PROVIDER]
                ),
                "status": "VALID" if not capability_reasons else "BLOCKED",
                "reason_codes": sorted(set(capability_reasons)),
            }
        )

    clean_reasons = sorted(set(str(reason) for reason in reasons if reason))
    status = "VALID" if not clean_reasons else "BLOCKED"
    return {
        "schema": OWNER_VALIDATION_SCHEMA,
        "valid": status == "VALID",
        "owner_validation_status": status,
        "owner_conflict_count": conflict_count,
        "missing_aggregate_owner_count": missing_aggregate_count,
        "missing_contract_owner_count": missing_contract_count,
        "capability_count": len(manifest_ids),
        "owner_record_count": len(owner_records),
        "capability_results": capability_results,
        "reason_codes": clean_reasons,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }
