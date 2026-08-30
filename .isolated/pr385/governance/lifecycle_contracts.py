from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.execution_contracts import sha256_json


LIFECYCLE_GOVERNANCE_SCHEMA = "usbay.lifecycle.governance.v1"
LIFECYCLE_GOVERNANCE_POLICY_VERSION = "usbay.pb-operational-lifecycle-governance.governed-lifecycle.v1"
LIFECYCLE_REASON_CODES = frozenset(
    {
        "UNKNOWN_CHANGE",
        "UNREGISTERED_CHANGE",
        "MISSING_CHANGE_REQUEST",
        "MISSING_RELEASE_APPROVAL",
        "MISSING_RUNTIME_APPROVAL",
        "MISSING_ROLLBACK_APPROVAL",
        "MISSING_INCIDENT_RECORD",
        "MISSING_MAINTENANCE_RECORD",
        "MISSING_AUDIT_LINKAGE",
        "MISSING_EVIDENCE_LINKAGE",
        "MISSING_LINEAGE",
        "MISSING_POLICY_BINDING",
        "CROSS_TENANT_CHANGE",
        "UNAUTHORIZED_RELEASE",
        "UNAUTHORIZED_PROMOTION",
        "UNAUTHORIZED_RUNTIME_CHANGE",
        "UNAUTHORIZED_ROLLBACK",
        "UNAUTHORIZED_INCIDENT_ACTION",
        "AUTO_RELEASE_FORBIDDEN",
        "AUTO_PROMOTION_FORBIDDEN",
        "AUTO_REMEDIATION_FORBIDDEN",
        "AUTO_ROLLBACK_FORBIDDEN",
        "AUTO_APPROVAL_FORBIDDEN",
        "LIFECYCLE_GOVERNANCE_BYPASS",
    }
)


@dataclass(frozen=True)
class LifecycleGovernanceValidation:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reason_codes": list(self.reason_codes)}


def canonical_lifecycle_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "change_id": str(record.get("change_id", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "workspace_id": str(record.get("workspace_id", "")),
        "change_request": record.get("change_request") is True,
        "registered_change": record.get("registered_change") is True,
        "release_approval": record.get("release_approval") is True,
        "runtime_approval": record.get("runtime_approval") is True,
        "rollback_approval": record.get("rollback_approval") is True,
        "incident_record": record.get("incident_record") is True,
        "maintenance_record": record.get("maintenance_record") is True,
        "policy_binding": record.get("policy_binding") is True,
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "change_status": str(record.get("change_status", "")),
        "release_status": str(record.get("release_status", "")),
        "promotion_status": str(record.get("promotion_status", "")),
        "runtime_status": str(record.get("runtime_status", "")),
        "rollback_status": str(record.get("rollback_status", "")),
        "incident_status": str(record.get("incident_status", "")),
        "maintenance_status": str(record.get("maintenance_status", "")),
        "policy_version": str(record.get("policy_version", "")),
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_lifecycle_governance_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_lifecycle_payload(record))


def validate_lifecycle_record(record: dict[str, Any] | None) -> LifecycleGovernanceValidation:
    if not isinstance(record, dict):
        return LifecycleGovernanceValidation(False, "BLOCKED", ("UNKNOWN_CHANGE",))

    reasons: list[str] = []
    if record.get("schema") != LIFECYCLE_GOVERNANCE_SCHEMA or not str(record.get("change_id", "")).strip():
        reasons.append("UNKNOWN_CHANGE")
    if record.get("registered_change") is not True:
        reasons.append("UNREGISTERED_CHANGE")
    if record.get("change_request") is not True:
        reasons.append("MISSING_CHANGE_REQUEST")
    if record.get("release_approval") is not True:
        reasons.append("MISSING_RELEASE_APPROVAL")
    if record.get("runtime_approval") is not True:
        reasons.append("MISSING_RUNTIME_APPROVAL")
    if record.get("rollback_approval") is not True:
        reasons.append("MISSING_ROLLBACK_APPROVAL")
    if record.get("incident_record") is not True:
        reasons.append("MISSING_INCIDENT_RECORD")
    if record.get("maintenance_record") is not True:
        reasons.append("MISSING_MAINTENANCE_RECORD")
    if record.get("policy_binding") is not True or not str(record.get("policy_version", "")).strip():
        reasons.append("MISSING_POLICY_BINDING")
    if not str(record.get("audit_hash", "")).strip():
        reasons.append("MISSING_AUDIT_LINKAGE")
    if not str(record.get("evidence_hash", "")).strip():
        reasons.append("MISSING_EVIDENCE_LINKAGE")
    if not str(record.get("lineage_hash", "")).strip():
        reasons.append("MISSING_LINEAGE")
    if str(record.get("change_status", "")) != "GOVERNED":
        reasons.append("MISSING_CHANGE_REQUEST")
    if str(record.get("release_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_RELEASE")
    if str(record.get("promotion_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_PROMOTION")
    if str(record.get("runtime_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_RUNTIME_CHANGE")
    if str(record.get("rollback_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_ROLLBACK")
    if str(record.get("incident_status", "")) != "AUTHORIZED":
        reasons.append("UNAUTHORIZED_INCIDENT_ACTION")
    if str(record.get("maintenance_status", "")) != "GOVERNED":
        reasons.append("MISSING_MAINTENANCE_RECORD")
    if record.get("tenant_id") and record.get("requesting_tenant_id") and record.get("tenant_id") != record.get("requesting_tenant_id"):
        reasons.append("CROSS_TENANT_CHANGE")
    if record.get("workspace_id") and record.get("requesting_workspace_id") and record.get("workspace_id") != record.get("requesting_workspace_id"):
        reasons.append("CROSS_TENANT_CHANGE")

    forbidden_flags = {
        "execution": "LIFECYCLE_GOVERNANCE_BYPASS",
        "deployment": "LIFECYCLE_GOVERNANCE_BYPASS",
        "runtime_modification": "LIFECYCLE_GOVERNANCE_BYPASS",
        "policy_modification": "LIFECYCLE_GOVERNANCE_BYPASS",
        "connector_write": "LIFECYCLE_GOVERNANCE_BYPASS",
        "governance_bypass": "LIFECYCLE_GOVERNANCE_BYPASS",
        "auto_release": "AUTO_RELEASE_FORBIDDEN",
        "auto_promotion": "AUTO_PROMOTION_FORBIDDEN",
        "auto_remediation": "AUTO_REMEDIATION_FORBIDDEN",
        "auto_rollback": "AUTO_ROLLBACK_FORBIDDEN",
        "auto_approval": "AUTO_APPROVAL_FORBIDDEN",
    }
    for field, reason in forbidden_flags.items():
        if record.get(field) is True:
            reasons.append(reason)
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("LIFECYCLE_GOVERNANCE_BYPASS")
    if record.get("lifecycle_governance_hash") and record.get("lifecycle_governance_hash") != compute_lifecycle_governance_hash(record):
        return LifecycleGovernanceValidation(False, "TAMPER_DETECTED", ("LIFECYCLE_GOVERNANCE_BYPASS",))

    clean = tuple(sorted(set(reasons)))
    return LifecycleGovernanceValidation(not clean, "GOVERNED" if not clean else "BLOCKED", clean)


def build_lifecycle_record(
    *,
    change_id: str,
    tenant_id: str,
    workspace_id: str,
    change_request: bool,
    registered_change: bool,
    release_approval: bool,
    runtime_approval: bool,
    rollback_approval: bool,
    incident_record: bool,
    maintenance_record: bool,
    policy_binding: bool,
    audit_hash: str,
    evidence_hash: str,
    lineage_hash: str,
    change_status: str,
    release_status: str,
    promotion_status: str,
    runtime_status: str,
    rollback_status: str,
    incident_status: str,
    maintenance_status: str,
    policy_version: str,
    execution: bool = False,
    deployment: bool = False,
    runtime_modification: bool = False,
    policy_modification: bool = False,
    connector_write: bool = False,
    auto_release: bool = False,
    auto_promotion: bool = False,
    auto_remediation: bool = False,
    auto_rollback: bool = False,
    auto_approval: bool = False,
    governance_bypass: bool = False,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = False,
) -> dict[str, Any]:
    record = {
        "schema": LIFECYCLE_GOVERNANCE_SCHEMA,
        "change_id": str(change_id),
        "tenant_id": str(tenant_id),
        "workspace_id": str(workspace_id),
        "change_request": bool(change_request),
        "registered_change": bool(registered_change),
        "release_approval": bool(release_approval),
        "runtime_approval": bool(runtime_approval),
        "rollback_approval": bool(rollback_approval),
        "incident_record": bool(incident_record),
        "maintenance_record": bool(maintenance_record),
        "policy_binding": bool(policy_binding),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "lineage_hash": str(lineage_hash),
        "change_status": str(change_status),
        "release_status": str(release_status),
        "promotion_status": str(promotion_status),
        "runtime_status": str(runtime_status),
        "rollback_status": str(rollback_status),
        "incident_status": str(incident_status),
        "maintenance_status": str(maintenance_status),
        "policy_version": str(policy_version),
        "execution": bool(execution),
        "deployment": bool(deployment),
        "runtime_modification": bool(runtime_modification),
        "policy_modification": bool(policy_modification),
        "connector_write": bool(connector_write),
        "auto_release": bool(auto_release),
        "auto_promotion": bool(auto_promotion),
        "auto_remediation": bool(auto_remediation),
        "auto_rollback": bool(auto_rollback),
        "auto_approval": bool(auto_approval),
        "governance_bypass": bool(governance_bypass),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "fail_closed": bool(fail_closed),
        "lifecycle_governance_hash": "",
    }
    record["lifecycle_governance_hash"] = compute_lifecycle_governance_hash(record)
    return record
