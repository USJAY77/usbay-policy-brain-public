from __future__ import annotations

from typing import Any

from governance.aggregate_owner_registry import AGGREGATE_OWNER_REGISTRY
from governance.owner_roles import AGGREGATE_OWNER, CONTRACT_OWNER, DEPRECATED_PROVIDER, PROVIDER
from governance.provider_registry import provider_records


PROVIDER_INVENTORY_SCHEMA = "usbay.governance.provider_inventory.v1"


def deprecated_provider_inventory(
    owner_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    owners = tuple(dict(record) for record in (owner_records if owner_records is not None else AGGREGATE_OWNER_REGISTRY))
    providers = provider_records(owners)
    deprecated = [dict(record) for record in providers if record.get("owner_role") == DEPRECATED_PROVIDER]
    ownership_claims = [
        dict(record)
        for record in owners
        if record.get("owner_role") in {AGGREGATE_OWNER, CONTRACT_OWNER}
    ]
    return {
        "schema": PROVIDER_INVENTORY_SCHEMA,
        "provider_status": "VALID",
        "provider_count": len([record for record in providers if record.get("owner_role") == PROVIDER]),
        "deprecated_provider_count": len(deprecated),
        "deprecated_providers": deprecated,
        "ownership_claims": ownership_claims,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }
