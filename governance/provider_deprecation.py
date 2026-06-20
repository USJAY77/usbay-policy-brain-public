from __future__ import annotations

from typing import Any

from governance.aggregate_owner_registry import AGGREGATE_OWNER_REGISTRY
from governance.execution_contracts import sha256_json
from governance.owner_roles import AGGREGATE_OWNER, CONTRACT_OWNER, DEPRECATED_PROVIDER
from governance.owner_validation import validate_owner_registry
from governance.provider_inventory import deprecated_provider_inventory


PROVIDER_DEPRECATION_SCHEMA = "usbay.governance.provider_deprecation.v1"
PROVIDER_AUDIT_SCHEMA = "usbay.governance.provider_audit.v1"
PROVIDER_MIGRATION_REGISTRY_SCHEMA = "usbay.governance.provider_migration_registry.v1"
PROVIDER_DEPRECATION_REPORT_SCHEMA = "usbay.governance.provider_deprecation_report.v1"
REASON_PROVIDER_OWNERSHIP_CLAIM = "PROVIDER_OWNERSHIP_CLAIM"
REASON_PROVIDER_MAPPING_MISSING = "PROVIDER_MAPPING_MISSING"
REASON_AGGREGATE_OWNER_MISSING = "AGGREGATE_OWNER_MISSING"
REASON_CONTRACT_OWNER_MISSING = "CONTRACT_OWNER_MISSING"
REASON_PROVIDER_DASHBOARD_TRUTH = "PROVIDER_DASHBOARD_TRUTH"
REASON_PROVIDER_STATUS_FIELD_OWNER = "PROVIDER_STATUS_FIELD_OWNER"
REASON_PROVIDER_REASON_CODE_OWNER = "PROVIDER_REASON_CODE_OWNER"
REASON_PROVIDER_DECISION_OVERRIDE = "PROVIDER_DECISION_OVERRIDE"
REASON_PROVIDER_TRUTH_OWNERSHIP = "PROVIDER_TRUTH_OWNERSHIP"


def validate_provider_deprecation(
    owner_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    owners = tuple(dict(record) for record in (owner_records if owner_records is not None else AGGREGATE_OWNER_REGISTRY))
    inventory = deprecated_provider_inventory(owners)
    owner_validation = validate_owner_registry(records=owners)
    capability_results = {
        row["capability_id"]: row
        for row in owner_validation["capability_results"]
    }
    ownership_claim_modules = {
        str(record.get("module", ""))
        for record in owners
        if record.get("owner_role") in {AGGREGATE_OWNER, CONTRACT_OWNER}
    }

    provider_rows: list[dict[str, Any]] = []
    reasons: list[str] = []
    for provider in inventory["deprecated_providers"]:
        capability_id = str(provider.get("capability_id", ""))
        module = str(provider.get("module", ""))
        capability = capability_results.get(capability_id)
        row_reasons: list[str] = []
        if capability is None:
            row_reasons.append(REASON_PROVIDER_MAPPING_MISSING)
        else:
            if capability.get("aggregate_owner_count") != 1:
                row_reasons.append(REASON_AGGREGATE_OWNER_MISSING)
            if capability.get("contract_owner_count", 0) < 1:
                row_reasons.append(REASON_CONTRACT_OWNER_MISSING)
        if module in ownership_claim_modules:
            row_reasons.append(REASON_PROVIDER_OWNERSHIP_CLAIM)
        if _truthy(provider.get("dashboard_truth_allowed")) or provider.get("dashboard_fields"):
            row_reasons.append(REASON_PROVIDER_DASHBOARD_TRUTH)
        if _truthy(provider.get("status_field_owner")) or provider.get("status_fields"):
            row_reasons.append(REASON_PROVIDER_STATUS_FIELD_OWNER)
        if _truthy(provider.get("reason_code_owner")) or provider.get("reason_codes"):
            row_reasons.append(REASON_PROVIDER_REASON_CODE_OWNER)
        if _truthy(provider.get("aggregate_decision_override_allowed")) or _truthy(provider.get("overrides_aggregate_owner")):
            row_reasons.append(REASON_PROVIDER_DECISION_OVERRIDE)
        reasons.extend(row_reasons)
        provider_rows.append(
            {
                "capability_id": capability_id,
                "module": module,
                "owner_role": DEPRECATED_PROVIDER,
                "aggregate_owner": _owner_module(owners, capability_id, AGGREGATE_OWNER),
                "contract_owner": _owner_module(owners, capability_id, CONTRACT_OWNER),
                "provider": str(provider.get("provider", "")),
                "deprecated_provider": str(provider.get("deprecated_provider", module)),
                "dashboard_truth_allowed": False,
                "status_field_owner": False,
                "reason_code_owner": False,
                "aggregate_decision_override_allowed": False,
                "provider_status": "VALID" if not row_reasons else "BLOCKED",
                "reason_codes": sorted(set(row_reasons)),
            }
        )

    clean_reasons = sorted(set(reasons))
    return {
        "schema": PROVIDER_DEPRECATION_SCHEMA,
        "provider_status": "VALID" if not clean_reasons else "BLOCKED",
        "provider_drift_count": len([row for row in provider_rows if row["provider_status"] != "VALID"]),
        "deprecated_provider_count": len(provider_rows),
        "deprecated_provider_inventory": provider_rows,
        "reason_codes": clean_reasons,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


def provider_drift_report(
    owner_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    validation = validate_provider_deprecation(owner_records)
    return {
        "schema": "usbay.governance.provider_drift_report.v1",
        "provider_status": validation["provider_status"],
        "provider_drift_count": validation["provider_drift_count"],
        "drifted_providers": [
            row for row in validation["deprecated_provider_inventory"] if row["provider_status"] != "VALID"
        ],
        "reason_codes": validation["reason_codes"],
        "read_only": True,
    }


def migration_readiness_report(
    owner_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    validation = validate_provider_deprecation(owner_records)
    ready = validation["provider_status"] == "VALID"
    return {
        "schema": "usbay.governance.provider_migration_readiness.v1",
        "migration_readiness_status": "READY" if ready else "BLOCKED",
        "provider_status": validation["provider_status"],
        "provider_drift_count": validation["provider_drift_count"],
        "deprecated_provider_count": validation["deprecated_provider_count"],
        "reason_codes": validation["reason_codes"],
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


def provider_migration_registry() -> dict[str, Any]:
    validation = validate_provider_deprecation()
    records: list[dict[str, Any]] = []
    for provider in validation["deprecated_provider_inventory"]:
        provider_id = str(provider.get("module", ""))
        owner = str(provider.get("aggregate_owner", ""))
        status = "READY_FOR_REMOVAL" if provider.get("provider_status") == "VALID" and owner else "BLOCKED"
        records.append(
            {
                "provider_id": provider_id,
                "capability_id": str(provider.get("capability_id", "")),
                "aggregate_owner": owner,
                "contract_owner": str(provider.get("contract_owner", "")),
                "replacement_owner": owner,
                "replacement_provider": owner,
                "migration_status": status,
                "removal_candidate": status == "READY_FOR_REMOVAL",
                "reason_codes": list(provider.get("reason_codes", [])),
                "dashboard_truth_owner": False,
                "runtime_truth_owner": False,
                "audit_truth_owner": False,
                "evidence_truth_owner": False,
                "lineage_truth_owner": False,
            }
        )
    return {
        "schema": PROVIDER_MIGRATION_REGISTRY_SCHEMA,
        "provider_migration_status": "VALID" if validation["provider_status"] == "VALID" else "BLOCKED",
        "deprecated_provider_count": validation["deprecated_provider_count"],
        "providers": records,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation_enabled": False,
        "auto_approval_enabled": False,
    }


def provider_deprecation_report() -> dict[str, Any]:
    validation = validate_provider_deprecation()
    migration = provider_migration_registry()
    providers = list(migration["providers"])
    orphaned = [row["provider_id"] for row in providers if not row["replacement_owner"] or not row["contract_owner"]]
    dead_paths = [row["provider_id"] for row in providers if row["migration_status"] == "READY_FOR_REMOVAL"]
    duplicate_paths = sorted(
        {
            row["provider_id"]
            for row in providers
            if sum(1 for candidate in providers if candidate["provider_id"] == row["provider_id"]) > 1
        }
    )
    truth_owners = [
        row["provider_id"]
        for row in providers
        if any(
            row.get(key) is True
            for key in (
                "dashboard_truth_owner",
                "runtime_truth_owner",
                "audit_truth_owner",
                "evidence_truth_owner",
                "lineage_truth_owner",
            )
        )
    ]
    reasons = list(validation["reason_codes"])
    if truth_owners:
        reasons.append(REASON_PROVIDER_TRUTH_OWNERSHIP)
    clean_reasons = sorted(set(reasons))
    return {
        "schema": PROVIDER_DEPRECATION_REPORT_SCHEMA,
        "provider_deprecation_status": "VALID" if not clean_reasons and not orphaned else "BLOCKED",
        "deprecated_provider_count": validation["deprecated_provider_count"],
        "providers": providers,
        "orphaned_providers": orphaned,
        "dead_ownership_paths": dead_paths,
        "duplicate_ownership_paths": duplicate_paths,
        "provider_truth_owners": truth_owners,
        "reason_codes": clean_reasons,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation_enabled": False,
        "auto_approval_enabled": False,
    }


def provider_audit_report(
    owner_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    validation = validate_provider_deprecation(owner_records)
    audit_payload = {
        "provider_status": validation["provider_status"],
        "provider_drift_count": validation["provider_drift_count"],
        "deprecated_provider_count": validation["deprecated_provider_count"],
        "reason_codes": validation["reason_codes"],
    }
    return {
        "schema": PROVIDER_AUDIT_SCHEMA,
        **audit_payload,
        "provider_audit_hash": sha256_json(audit_payload),
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


def empty_provider_deprecation_dashboard_state() -> dict[str, Any]:
    validation = validate_provider_deprecation()
    return {
        "provider_status": validation["provider_status"],
        "provider_drift_count": validation["provider_drift_count"],
        "deprecated_provider_count": validation["deprecated_provider_count"],
        "provider_reason_codes": validation["reason_codes"],
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


def _owner_module(owner_records: tuple[dict[str, Any], ...], capability_id: str, owner_role: str) -> str:
    for record in owner_records:
        if record.get("capability_id") == capability_id and record.get("owner_role") == owner_role:
            return str(record.get("module", ""))
    return ""


def _truthy(value: Any) -> bool:
    return value is True or str(value).upper() in {"TRUE", "YES", "1"}
