from __future__ import annotations

from collections import defaultdict
from typing import Any

from governance.aggregate_owner_registry import AGGREGATE_OWNER_REGISTRY
from governance.capability_manifest import CAPABILITY_MANIFEST
from governance.dashboard_owner_registry import DASHBOARD_OWNER_REGISTRY
from governance.owner_roles import AGGREGATE_OWNER
from governance.reason_code_registry import REASON_CODE_NAMESPACES


DUPLICATE_DETECTOR_SCHEMA = "usbay.governance.duplicate_detector.v1"


def detect_governance_duplicates(
    *,
    owner_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] = AGGREGATE_OWNER_REGISTRY,
    dashboard_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] = DASHBOARD_OWNER_REGISTRY,
    manifest: tuple[dict[str, Any], ...] = CAPABILITY_MANIFEST,
    reason_namespaces: dict[str, tuple[str, ...]] = REASON_CODE_NAMESPACES,
) -> dict[str, Any]:
    aggregate_owner_duplicates = _duplicate_capability_owners(owner_records, AGGREGATE_OWNER)
    dashboard_owner_duplicates = _duplicate_dashboard_owners(dashboard_records)
    duplicate_reason_codes = _duplicate_reason_codes(reason_namespaces)
    reason_namespace_duplicates = _duplicate_manifest_values(manifest, "reason_namespace")
    audit_owner_duplicates = _duplicate_normalized_owners(manifest, "audit_linkage")
    evidence_owner_duplicates = _duplicate_normalized_owners(manifest, "evidence_linkage")
    lineage_owner_duplicates = _duplicate_normalized_owners(manifest, "lineage_validation")
    duplicate_count = (
        len(aggregate_owner_duplicates)
        + len(dashboard_owner_duplicates)
        + len(duplicate_reason_codes)
        + len(reason_namespace_duplicates)
        + len(audit_owner_duplicates)
        + len(evidence_owner_duplicates)
        + len(lineage_owner_duplicates)
    )
    return {
        "schema": DUPLICATE_DETECTOR_SCHEMA,
        "duplicate_status": "VALID" if duplicate_count == 0 else "BLOCKED",
        "duplicate_owner_count": len(aggregate_owner_duplicates),
        "duplicate_dashboard_owner_count": len(dashboard_owner_duplicates),
        "duplicate_reason_code_owner_count": len(duplicate_reason_codes) + len(reason_namespace_duplicates),
        "duplicate_audit_owner_count": len(audit_owner_duplicates),
        "duplicate_evidence_owner_count": len(evidence_owner_duplicates),
        "duplicate_lineage_owner_count": len(lineage_owner_duplicates),
        "aggregate_owner_duplicates": aggregate_owner_duplicates,
        "dashboard_owner_duplicates": dashboard_owner_duplicates,
        "duplicate_reason_codes": duplicate_reason_codes,
        "duplicate_reason_namespaces": reason_namespace_duplicates,
        "audit_owner_duplicates": audit_owner_duplicates,
        "evidence_owner_duplicates": evidence_owner_duplicates,
        "lineage_owner_duplicates": lineage_owner_duplicates,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
    }


def _duplicate_capability_owners(records: tuple[dict[str, Any], ...] | list[dict[str, Any]], owner_role: str) -> list[str]:
    by_capability: dict[str, list[str]] = defaultdict(list)
    for record in records:
        if record.get("owner_role") == owner_role:
            by_capability[str(record.get("capability_id", ""))].append(str(record.get("module", "")))
    return sorted(capability_id for capability_id, modules in by_capability.items() if len(set(modules)) > 1)


def _duplicate_dashboard_owners(records: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> list[str]:
    by_capability: dict[str, list[str]] = defaultdict(list)
    for record in records:
        by_capability[str(record.get("capability_id", ""))].append(str(record.get("dashboard_owner_module", "")))
    return sorted(capability_id for capability_id, modules in by_capability.items() if len(set(modules)) > 1)


def _duplicate_reason_codes(namespaces: dict[str, tuple[str, ...]]) -> list[str]:
    owners: dict[str, list[str]] = defaultdict(list)
    for namespace, codes in namespaces.items():
        for code in codes:
            owners[str(code)].append(str(namespace))
    return sorted(code for code, owner_namespaces in owners.items() if len(set(owner_namespaces)) > 1)


def _duplicate_manifest_values(manifest: tuple[dict[str, Any], ...], key: str) -> list[str]:
    owners: dict[str, list[str]] = defaultdict(list)
    for capability in manifest:
        owners[str(capability.get(key, ""))].append(str(capability.get("capability_id", "")))
    return sorted(value for value, capabilities in owners.items() if value and len(set(capabilities)) > 1)


def _duplicate_normalized_owners(manifest: tuple[dict[str, Any], ...], control_id: str) -> list[str]:
    owners: dict[str, list[str]] = defaultdict(list)
    for capability in manifest:
        capability_id = str(capability.get("capability_id", ""))
        controls = tuple(str(control) for control in capability.get("controls", ()))
        if control_id in controls:
            owners[capability_id].append(capability_id)
    return sorted(owner for owner, capabilities in owners.items() if len(capabilities) > 1)
