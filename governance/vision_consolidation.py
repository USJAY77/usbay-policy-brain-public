from __future__ import annotations

from typing import Any

from governance.aggregate_owner_registry import AGGREGATE_OWNER_REGISTRY
from governance.audit_normalization import audit_normalization_report
from governance.capability_manifest import CAPABILITY_MANIFEST
from governance.evidence_normalization import evidence_normalization_report
from governance.lineage_normalization import lineage_normalization_report
from governance.owner_roles import AGGREGATE_OWNER, CONTRACT_OWNER, DEPRECATED_PROVIDER, PROVIDER
from governance.owner_validation import validate_owner_registry
from governance.reason_code_registry import REASON_CODE_NAMESPACES


VISION_CAPABILITY_ID = "vision_agent_control"
VISION_CONSOLIDATION_SCHEMA = "usbay.governance.vision_consolidation.v1"
REASON_VISION_CAPABILITY_MISSING = "VISION_CAPABILITY_MISSING"
REASON_VISION_OWNER_INVALID = "VISION_OWNER_INVALID"
REASON_VISION_CONTRACT_OWNER_MISSING = "VISION_CONTRACT_OWNER_MISSING"
REASON_VISION_PROVIDER_OWNERSHIP_AMBIGUITY = "VISION_PROVIDER_OWNERSHIP_AMBIGUITY"
REASON_VISION_REASON_NAMESPACE_INVALID = "VISION_REASON_NAMESPACE_INVALID"
REASON_VISION_CONTROL_MISSING = "VISION_CONTROL_MISSING"


def validate_vision_consolidation(
    owner_records: tuple[dict[str, Any], ...] | list[dict[str, Any]] = AGGREGATE_OWNER_REGISTRY,
    manifest: tuple[dict[str, Any], ...] = CAPABILITY_MANIFEST,
) -> dict[str, Any]:
    capability = _vision_capability(manifest)
    owners = tuple(dict(record) for record in owner_records)
    owner_validation = validate_owner_registry(records=owners, manifest=manifest)
    reasons: list[str] = []
    if capability is None:
        reasons.append(REASON_VISION_CAPABILITY_MISSING)
        controls: tuple[str, ...] = ()
        modules: tuple[str, ...] = ()
        reason_namespace = ""
    else:
        controls = tuple(str(control) for control in capability.get("controls", ()))
        modules = tuple(str(module) for module in capability.get("modules", ()))
        reason_namespace = str(capability.get("reason_namespace", ""))

    vision_owners = [record for record in owners if record.get("capability_id") == VISION_CAPABILITY_ID]
    aggregate_owners = [record for record in vision_owners if record.get("owner_role") == AGGREGATE_OWNER]
    contract_owners = [record for record in vision_owners if record.get("owner_role") == CONTRACT_OWNER]
    providers = [record for record in vision_owners if record.get("owner_role") in {PROVIDER, DEPRECATED_PROVIDER}]
    if len(aggregate_owners) != 1 or (modules and aggregate_owners[0].get("module") != modules[0]):
        reasons.append(REASON_VISION_OWNER_INVALID)
    if len(contract_owners) < 1:
        reasons.append(REASON_VISION_CONTRACT_OWNER_MISSING)
    if any(record.get("owner_role") in {AGGREGATE_OWNER, CONTRACT_OWNER} for record in providers):
        reasons.append(REASON_VISION_PROVIDER_OWNERSHIP_AMBIGUITY)
    if reason_namespace != "vision" or "vision" not in REASON_CODE_NAMESPACES:
        reasons.append(REASON_VISION_REASON_NAMESPACE_INVALID)
    for control in ("audit_linkage", "evidence_linkage", "lineage_validation", "human_approval", "execution_forbidden"):
        if control not in controls:
            reasons.append(REASON_VISION_CONTROL_MISSING)

    audit = _status_for_capability(audit_normalization_report(), "audit_status")
    evidence = _status_for_capability(evidence_normalization_report(), "evidence_status")
    lineage = _status_for_capability(lineage_normalization_report(), "lineage_status")
    clean_reasons = sorted(set(reasons + owner_validation["reason_codes"]))
    return {
        "schema": VISION_CONSOLIDATION_SCHEMA,
        "vision_consolidation_status": "VALID" if not clean_reasons else "BLOCKED",
        "capability_id": VISION_CAPABILITY_ID,
        "aggregate_owner": aggregate_owners[0]["module"] if aggregate_owners else "",
        "contract_owner": contract_owners[0]["module"] if contract_owners else "",
        "provider_count": len([record for record in vision_owners if record.get("owner_role") == PROVIDER]),
        "deprecated_provider_count": len([record for record in vision_owners if record.get("owner_role") == DEPRECATED_PROVIDER]),
        "audit_status": audit,
        "evidence_status": evidence,
        "lineage_status": lineage,
        "human_approval_status": "REQUIRED" if "human_approval" in controls else "BLOCKED",
        "reason_namespace": reason_namespace,
        "reason_codes": clean_reasons,
        "duplicate_owner_count": 1 if REASON_VISION_OWNER_INVALID in clean_reasons else 0,
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "connector_write_enabled": False,
        "auto_remediation_enabled": False,
        "auto_approval_enabled": False,
    }


def _vision_capability(manifest: tuple[dict[str, Any], ...]) -> dict[str, Any] | None:
    for capability in manifest:
        if capability.get("capability_id") == VISION_CAPABILITY_ID:
            return dict(capability)
    return None


def _status_for_capability(report: dict[str, Any], status_key: str) -> str:
    for row in report.get("capabilities", []):
        if row.get("capability_id") == VISION_CAPABILITY_ID:
            return str(row.get(status_key, "BLOCKED"))
    return "BLOCKED"
