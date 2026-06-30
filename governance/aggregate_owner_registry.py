from __future__ import annotations

from typing import Any

from governance.capability_manifest import CAPABILITY_MANIFEST
from governance.owner_roles import AGGREGATE_OWNER, CONTRACT_OWNER, OWNER_ROLES, PROVIDER


AGGREGATE_OWNER_REGISTRY_SCHEMA = "usbay.governance.aggregate_owner_registry.v1"


def _owner_records_from_manifest(capabilities: tuple[dict[str, Any], ...] = CAPABILITY_MANIFEST) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    for capability in capabilities:
        capability_id = str(capability.get("capability_id", ""))
        modules = tuple(str(module) for module in capability.get("modules", ()) if module)
        for index, module in enumerate(modules):
            if index == 0:
                owner_role = AGGREGATE_OWNER
            elif index == 1:
                owner_role = CONTRACT_OWNER
            else:
                owner_role = PROVIDER
            records.append(
                {
                    "capability_id": capability_id,
                    "module": module,
                    "owner_role": owner_role,
                    "source": "capability_manifest",
                }
            )
    return tuple(records)


AGGREGATE_OWNER_REGISTRY: tuple[dict[str, Any], ...] = _owner_records_from_manifest()


def list_owner_records() -> list[dict[str, Any]]:
    return [dict(record) for record in AGGREGATE_OWNER_REGISTRY]


def owner_records_for_capability(capability_id: str) -> list[dict[str, Any]]:
    return [dict(record) for record in AGGREGATE_OWNER_REGISTRY if record.get("capability_id") == capability_id]


def empty_owner_validation_dashboard_state() -> dict[str, Any]:
    from governance.owner_validation import validate_owner_registry

    validation = validate_owner_registry()
    return {
        "owner_validation_status": validation["owner_validation_status"],
        "owner_conflict_count": validation["owner_conflict_count"],
        "owner_reason_codes": validation["reason_codes"],
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }
