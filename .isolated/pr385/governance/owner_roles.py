from __future__ import annotations

from typing import Any


OWNER_ROLE_SCHEMA = "usbay.governance.owner_roles.v1"
AGGREGATE_OWNER = "aggregate_owner"
CONTRACT_OWNER = "contract_owner"
PROVIDER = "provider"
DEPRECATED_PROVIDER = "deprecated_provider"
OWNER_ROLES = frozenset({AGGREGATE_OWNER, CONTRACT_OWNER, PROVIDER, DEPRECATED_PROVIDER})


def list_owner_roles() -> tuple[str, ...]:
    return tuple(sorted(OWNER_ROLES))


def validate_owner_role(role: str) -> bool:
    return str(role) in OWNER_ROLES


def owner_role_registry() -> dict[str, Any]:
    return {
        "schema": OWNER_ROLE_SCHEMA,
        "owner_roles": list(list_owner_roles()),
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }
