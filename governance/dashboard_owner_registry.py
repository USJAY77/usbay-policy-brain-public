from __future__ import annotations

from typing import Any

from governance.aggregate_owner_registry import AGGREGATE_OWNER_REGISTRY
from governance.capability_manifest import CAPABILITY_MANIFEST
from governance.owner_roles import AGGREGATE_OWNER


DASHBOARD_OWNER_REGISTRY_SCHEMA = "usbay.governance.dashboard_owner_registry.v1"


def _manifest_by_capability(manifest: tuple[dict[str, Any], ...]) -> dict[str, dict[str, Any]]:
    return {str(capability.get("capability_id", "")): dict(capability) for capability in manifest if capability.get("capability_id")}


def dashboard_owner_records(
    owner_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] = AGGREGATE_OWNER_REGISTRY,
    manifest: tuple[dict[str, Any], ...] = CAPABILITY_MANIFEST,
) -> tuple[dict[str, Any], ...]:
    manifest_by_id = _manifest_by_capability(manifest)
    records: list[dict[str, Any]] = []
    for owner_record in owner_records:
        capability_id = str(owner_record.get("capability_id", ""))
        if owner_record.get("owner_role") != AGGREGATE_OWNER or capability_id not in manifest_by_id:
            continue
        capability = manifest_by_id[capability_id]
        records.append(
            {
                "capability_id": capability_id,
                "dashboard_owner_module": str(owner_record.get("module", "")),
                "owner_role": AGGREGATE_OWNER,
                "dashboard_fields": tuple(str(field) for field in capability.get("dashboard_states", ()) if field),
                "source": "aggregate_owner_registry",
                "read_only": True,
                "execution_enabled": False,
                "deployment_enabled": False,
                "runtime_modification_enabled": False,
            }
        )
    return tuple(records)


DASHBOARD_OWNER_REGISTRY: tuple[dict[str, Any], ...] = dashboard_owner_records()


def list_dashboard_owner_records() -> list[dict[str, Any]]:
    return [dict(record) for record in DASHBOARD_OWNER_REGISTRY]


def dashboard_owner_records_for_capability(capability_id: str) -> list[dict[str, Any]]:
    return [dict(record) for record in DASHBOARD_OWNER_REGISTRY if record.get("capability_id") == capability_id]
