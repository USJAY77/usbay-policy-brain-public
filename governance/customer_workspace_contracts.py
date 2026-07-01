from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


CUSTOMER_WORKSPACE_SCHEMA = "usbay.customer.workspace.v1"
WORKSPACE_ACCESS_SCHEMA = "usbay.customer.workspace_access.v1"
WORKSPACE_LIFECYCLE_SCHEMA = "usbay.customer.workspace_lifecycle.v1"
CUSTOMER_WORKSPACE_POLICY_VERSION = "usbay.pb-customer-workspace.governed-customer-workspace.v1"

ALLOWED_WORKSPACE_STATES = frozenset(
    {"DRAFT", "REVIEW_REQUIRED", "APPROVED", "ACTIVE", "SUSPENDED", "ARCHIVED", "BLOCKED"}
)
FAIL_CLOSED_REASON_CODES = frozenset(
    {
        "UNKNOWN_WORKSPACE",
        "MISSING_TENANT",
        "MISSING_POLICY",
        "MISSING_AUDIT",
        "MISSING_EVIDENCE",
        "CROSS_TENANT_ACCESS",
        "NO_HUMAN_APPROVAL",
        "AUTO_ONBOARDING_FORBIDDEN",
        "CONNECTOR_WRITE_FORBIDDEN",
    }
)
REQUIRED_WORKSPACE_FIELDS = (
    "workspace_id",
    "workspace_name",
    "tenant_id",
    "workspace_state",
    "policy_hash",
    "audit_hash",
    "evidence_hash",
    "lineage_hash",
    "human_approval",
    "reason_codes",
    "created_at",
    "fail_closed",
)
SENSITIVE_MARKERS = (
    "password",
    "secret",
    "token",
    "cookie",
    "authorization",
    "api_key",
    "private_key",
    "raw_payload",
    "raw_screenshot",
)


@dataclass(frozen=True)
class CustomerWorkspaceValidation:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reason_codes": list(self.reason_codes)}


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def contains_sensitive_marker(value: Any) -> bool:
    if isinstance(value, dict):
        text = " ".join(str(item).lower() for pair in value.items() for item in pair)
    elif isinstance(value, list):
        text = " ".join(str(item).lower() for item in value)
    else:
        text = str(value).lower()
    return any(marker in text for marker in SENSITIVE_MARKERS)


def canonical_workspace_payload(workspace: dict[str, Any]) -> dict[str, Any]:
    return {
        "workspace_id": str(workspace.get("workspace_id", "")),
        "workspace_name": str(workspace.get("workspace_name", "")),
        "tenant_id": str(workspace.get("tenant_id", "")),
        "workspace_state": str(workspace.get("workspace_state", "")),
        "policy_hash": str(workspace.get("policy_hash", "")),
        "audit_hash": str(workspace.get("audit_hash", "")),
        "evidence_hash": str(workspace.get("evidence_hash", "")),
        "lineage_hash": str(workspace.get("lineage_hash", "")),
        "human_approval": workspace.get("human_approval") is True,
        "reason_codes": sorted(str(code) for code in workspace.get("reason_codes", []) if code),
        "created_at": str(workspace.get("created_at", "")),
        "fail_closed": workspace.get("fail_closed") is True,
    }


def compute_workspace_hash(workspace: dict[str, Any]) -> str:
    return sha256_json(canonical_workspace_payload(workspace))


def validate_customer_workspace(workspace: dict[str, Any] | None) -> CustomerWorkspaceValidation:
    if not isinstance(workspace, dict):
        return CustomerWorkspaceValidation(False, "BLOCKED", ("UNKNOWN_WORKSPACE",))
    reasons: list[str] = []
    if workspace.get("schema") != CUSTOMER_WORKSPACE_SCHEMA:
        reasons.append("UNKNOWN_WORKSPACE")
    for field in REQUIRED_WORKSPACE_FIELDS:
        if workspace.get(field) in ("", None):
            reasons.append(f"WORKSPACE_{field.upper()}_MISSING")
    if not str(workspace.get("tenant_id", "")).strip():
        reasons.append("MISSING_TENANT")
    if not str(workspace.get("policy_hash", "")).strip():
        reasons.append("MISSING_POLICY")
    if not str(workspace.get("audit_hash", "")).strip():
        reasons.append("MISSING_AUDIT")
    if not str(workspace.get("evidence_hash", "")).strip():
        reasons.append("MISSING_EVIDENCE")
    if not str(workspace.get("lineage_hash", "")).strip():
        reasons.append("WORKSPACE_LINEAGE_MISSING")
    state = str(workspace.get("workspace_state", ""))
    if state not in ALLOWED_WORKSPACE_STATES:
        reasons.append(f"WORKSPACE_STATE_UNKNOWN:{state or 'MISSING'}")
    if workspace.get("human_approval") is not True:
        reasons.append("NO_HUMAN_APPROVAL")
    if workspace.get("auto_onboarding") is True:
        reasons.append("AUTO_ONBOARDING_FORBIDDEN")
    if workspace.get("auto_activation") is True:
        reasons.append("AUTO_ACTIVATION_FORBIDDEN")
    if workspace.get("auto_archive") is True:
        reasons.append("AUTO_ARCHIVE_FORBIDDEN")
    if parse_timestamp(workspace.get("created_at")) is None:
        reasons.append("WORKSPACE_CREATED_AT_INVALID")
    if not isinstance(workspace.get("reason_codes"), list):
        reasons.append("WORKSPACE_REASON_CODES_MALFORMED")
    if contains_sensitive_marker(workspace):
        reasons.append("WORKSPACE_SENSITIVE_PAYLOAD_BLOCKED")
    if workspace.get("workspace_hash") and workspace.get("workspace_hash") != compute_workspace_hash(workspace):
        return CustomerWorkspaceValidation(False, "TAMPER_DETECTED", ("WORKSPACE_HASH_MISMATCH",))
    status = "BLOCKED" if reasons else state
    return CustomerWorkspaceValidation(not reasons and status in {"APPROVED", "ACTIVE"}, status, tuple(sorted(set(reasons))))


def build_customer_workspace(
    *,
    workspace_id: str,
    workspace_name: str,
    tenant_id: str,
    workspace_state: str,
    policy_hash: str,
    audit_hash: str,
    evidence_hash: str,
    lineage_hash: str,
    human_approval: bool,
    created_at: str,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = True,
) -> dict[str, Any]:
    workspace = {
        "schema": CUSTOMER_WORKSPACE_SCHEMA,
        "workspace_id": str(workspace_id),
        "workspace_name": str(workspace_name),
        "tenant_id": str(tenant_id),
        "workspace_state": str(workspace_state),
        "policy_hash": str(policy_hash),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "lineage_hash": str(lineage_hash),
        "human_approval": bool(human_approval),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "created_at": str(created_at),
        "fail_closed": bool(fail_closed),
        "workspace_hash": "",
    }
    workspace["workspace_hash"] = compute_workspace_hash(workspace)
    return workspace
