from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.connector_contracts import build_connector_audit_record, validate_read_request, validate_read_result
from governance.connector_capabilities import evaluate_connector_capabilities
from governance.connector_contracts import validate_connector_governance_record
from governance.connector_evidence import evaluate_connector_evidence
from governance.connector_lineage import evaluate_connector_lineage
from governance.connector_permissions import evaluate_connector_permissions
from governance.connector_registry import GovernedConnectorRegistry, connector_available
from governance.external_api_governance import evaluate_external_api_governance


DECISION_ALLOWED_READ_ONLY = "CONNECTOR_READ_ALLOWED"
DECISION_BLOCKED = "CONNECTOR_BLOCKED"


@dataclass(frozen=True)
class ConnectorGovernanceResult:
    decision: str
    reason_codes: tuple[str, ...]
    audit_record: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "reason_codes": list(self.reason_codes), "audit_record": self.audit_record}


def _now_text(now: datetime | None) -> str:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return effective_now.isoformat().replace("+00:00", "Z")


def _append_reason(reasons: list[str], code: str) -> None:
    if code not in reasons:
        reasons.append(code)


def evaluate_connector_read_request(
    *,
    request: dict[str, Any] | None,
    registry: dict[str, Any] | None,
    now: datetime | None = None,
) -> ConnectorGovernanceResult:
    generated_at = _now_text(now)
    reasons: list[str] = []
    validation = validate_read_request(request)
    if not validation.valid:
        reasons.extend(validation.reason_codes)
    connector_type = str(request.get("connector_type", "") if isinstance(request, dict) else "")
    available, availability_reasons = connector_available(registry, connector_type)
    if not available:
        reasons.extend(availability_reasons)
    decision = DECISION_BLOCKED if reasons else DECISION_ALLOWED_READ_ONLY
    audit = build_connector_audit_record(request=request, decision=decision, reason_codes=reasons, generated_at=generated_at)
    return ConnectorGovernanceResult(decision=decision, reason_codes=tuple(sorted(set(reasons))), audit_record=audit)


def evaluate_connector_read_result(result: dict[str, Any] | None) -> tuple[bool, tuple[str, ...]]:
    validation = validate_read_result(result)
    if not validation.valid:
        return False, validation.reason_codes
    if not str(result.get("evidence_manifest_id", "")).strip():
        return False, ("CONNECTOR_EVIDENCE_MANIFEST_ID_MISSING",)
    if not str(result.get("audit_hash", "")).strip():
        return False, ("CONNECTOR_AUDIT_HASH_MISSING",)
    if not str(result.get("lineage_hash", "")).strip():
        return False, ("CONNECTOR_LINEAGE_HASH_MISSING",)
    if not str(result.get("policy_version", "")).strip():
        return False, ("CONNECTOR_POLICY_VERSION_MISSING",)
    return True, ()


def evaluate_connector_governance(
    *,
    record: dict[str, Any] | None,
    registry: GovernedConnectorRegistry | None = None,
    requesting_tenant_id: str = "",
    requesting_workspace_id: str = "",
) -> dict[str, Any]:
    reasons: list[str] = []
    validation = validate_connector_governance_record(record)
    if not validation.valid:
        reasons.extend(validation.reason_codes or ("UNKNOWN_CONNECTOR",))
    if isinstance(record, dict):
        if requesting_tenant_id and record.get("tenant_id") != requesting_tenant_id:
            reasons.append("CROSS_TENANT_CONNECTOR")
        if requesting_workspace_id and record.get("workspace_id") != requesting_workspace_id:
            reasons.append("CROSS_TENANT_CONNECTOR")
    capabilities = evaluate_connector_capabilities(record)
    permissions = evaluate_connector_permissions(record)
    external_api = evaluate_external_api_governance(record)
    lineage = evaluate_connector_lineage(record)
    evidence = evaluate_connector_evidence(record)
    registry_records = registry.list_connectors() if isinstance(registry, GovernedConnectorRegistry) else ([record] if isinstance(record, dict) else [])
    registry_summary = GovernedConnectorRegistry(registry_records).summary()
    for result in (capabilities, permissions, external_api, lineage, evidence, registry_summary):
        reasons.extend(result.get("reason_codes", []))
    reason_codes = sorted(set(str(reason) for reason in reasons if reason))
    status = "GOVERNED" if not reason_codes else "BLOCKED"
    return {
        "schema": "usbay.connector.governance.state.v1",
        "connector_status": status,
        "connector_registry_status": registry_summary["connector_registry_status"],
        "connector_capability_status": capabilities["connector_capability_status"],
        "connector_permission_status": permissions["connector_permission_status"],
        "external_api_status": external_api["external_api_status"],
        "connector_reason_codes": reason_codes,
        "fail_closed": status == "BLOCKED",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "connector_execution_enabled": False,
        "connector_write_enabled": False,
        "api_invocation_enabled": False,
        "email_send_enabled": False,
        "calendar_write_enabled": False,
        "repository_write_enabled": False,
        "file_write_enabled": False,
        "auto_remediation": False,
        "auto_approval": False,
    }
