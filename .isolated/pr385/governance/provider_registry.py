from __future__ import annotations

from typing import Any

from governance.aggregate_owner_registry import AGGREGATE_OWNER_REGISTRY
from governance.owner_roles import AGGREGATE_OWNER, CONTRACT_OWNER, DEPRECATED_PROVIDER, PROVIDER


PROVIDER_REGISTRY_SCHEMA = "usbay.governance.provider_registry.v1"

DEPRECATED_PROVIDER_MODULES: dict[str, tuple[str, ...]] = {
    "release_gate": ("governance.release_governance", "governance.release_readiness", "governance.release_manifest", "governance.release_integrity"),
    "lifecycle_governance": ("governance.release_governance", "governance.runtime_governance"),
    "document_governance": ("governance.document_review", "governance.document_versioning", "governance.document_classification"),
    "commercial_governance": (
        "governance.customer_readiness",
        "governance.customer_verification",
        "governance.license_registry",
        "governance.license_entitlements",
        "governance.license_lifecycle",
        "governance.customer_commercial_governance",
        "governance.contract_governance",
        "governance.subscription_governance",
        "governance.billing_governance",
        "governance.invoice_governance",
        "governance.pricing_governance",
        "governance.renewal_governance",
    ),
}


def provider_records(owner_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None) -> tuple[dict[str, Any], ...]:
    records = tuple(dict(record) for record in (owner_records if owner_records is not None else AGGREGATE_OWNER_REGISTRY))
    owner_modules = _owner_modules_by_capability(records)
    providers = [
        _provider_metadata(record, owner_modules)
        for record in records
        if record.get("owner_role") in {PROVIDER, DEPRECATED_PROVIDER}
    ]
    for capability_id, modules in DEPRECATED_PROVIDER_MODULES.items():
        for module in modules:
            providers.append(
                {
                    "capability_id": capability_id,
                    "module": module,
                    "owner_role": DEPRECATED_PROVIDER,
                    "source": "ownership_migration",
                    "deprecation_reason": "duplicate_ownership_path",
                    "aggregate_owner": owner_modules.get(capability_id, {}).get(AGGREGATE_OWNER, ""),
                    "contract_owner": owner_modules.get(capability_id, {}).get(CONTRACT_OWNER, ""),
                    "provider": "",
                    "deprecated_provider": module,
                    "dashboard_truth_allowed": False,
                    "status_field_owner": False,
                    "reason_code_owner": False,
                    "aggregate_decision_override_allowed": False,
                }
            )
    return tuple(providers)


def provider_registry_summary(owner_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None) -> dict[str, Any]:
    records = provider_records(owner_records)
    return {
        "schema": PROVIDER_REGISTRY_SCHEMA,
        "provider_count": len([record for record in records if record.get("owner_role") == PROVIDER]),
        "deprecated_provider_count": len([record for record in records if record.get("owner_role") == DEPRECATED_PROVIDER]),
        "providers": [dict(record) for record in records],
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


def _owner_modules_by_capability(records: tuple[dict[str, Any], ...]) -> dict[str, dict[str, str]]:
    owners: dict[str, dict[str, str]] = {}
    for record in records:
        capability_id = str(record.get("capability_id", ""))
        owner_role = str(record.get("owner_role", ""))
        module = str(record.get("module", ""))
        if owner_role not in {AGGREGATE_OWNER, CONTRACT_OWNER}:
            continue
        owners.setdefault(capability_id, {})[owner_role] = module
    return owners


def _provider_metadata(record: dict[str, Any], owner_modules: dict[str, dict[str, str]]) -> dict[str, Any]:
    capability_id = str(record.get("capability_id", ""))
    module = str(record.get("module", ""))
    owner_role = str(record.get("owner_role", ""))
    provider_module = module if owner_role == PROVIDER else ""
    deprecated_provider_module = module if owner_role == DEPRECATED_PROVIDER else ""
    return {
        **dict(record),
        "aggregate_owner": owner_modules.get(capability_id, {}).get(AGGREGATE_OWNER, ""),
        "contract_owner": owner_modules.get(capability_id, {}).get(CONTRACT_OWNER, ""),
        "provider": provider_module,
        "deprecated_provider": deprecated_provider_module,
        "dashboard_truth_allowed": False,
        "status_field_owner": False,
        "reason_code_owner": False,
        "aggregate_decision_override_allowed": False,
    }
