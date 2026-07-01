from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


EXECUTION_REQUEST_SCHEMA = "usbay.execution.request.v1"
EXECUTION_APPROVAL_SCHEMA = "usbay.execution.approval.v1"
EXECUTION_AUDIT_SCHEMA = "usbay.execution.audit_record.v1"

EXECUTION_POLICY_VERSION = "usbay.pb-exec.governed-execution-framework.v1"

PREVIEW_CAPABILITIES = frozenset(
    {
        "READ_ONLY_NAVIGATION",
        "FILE_READ",
        "ISSUE_COMMENT_DRAFT",
        "PR_DESCRIPTION_DRAFT",
        "REPORT_GENERATION",
        "DASHBOARD_PREVIEW",
        "GOVERNANCE_STATUS_READ",
    }
)

BLOCKED_CAPABILITIES = frozenset(
    {
        "FILE_WRITE",
        "FILE_DELETE",
        "SHELL_EXECUTION",
        "PUSH_CODE",
        "MERGE_PR",
        "BROWSER_CLICK",
        "BROWSER_TYPE",
        "SUBMIT_FORM",
        "LOGIN",
        "SECRET_ACCESS",
        "PAYMENT",
        "SEND_MESSAGE",
        "PRODUCTION_DEPLOY",
    }
)

REQUIRED_REQUEST_FIELDS = (
    "schema",
    "request_id",
    "proposal_id",
    "capability",
    "target",
    "parameters",
    "requested_by",
    "requested_at",
    "policy_version",
    "runtime_state_hash",
    "pbsec_state_hash",
    "vision_audit_hash",
    "requires_human_approval",
    "risk_level",
)

REQUIRED_APPROVAL_FIELDS = (
    "schema",
    "approval_id",
    "request_id",
    "approved_by_human",
    "approver_role",
    "approved_scope",
    "approved_at",
    "approval_signature_or_hash",
    "no_ai_auto_approval",
)

AI_APPROVER_IDENTITIES = frozenset({"codex", "ai-agent", "ai_agent", "agent", "assistant"})
PREVIEW_APPROVAL_SCOPES = frozenset({"PREVIEW_ONLY", "REVIEW_ONLY", "READ_ONLY"})

SECRET_MARKERS = (
    "password",
    "secret",
    "token",
    "cookie",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "session",
)


@dataclass(frozen=True)
class ContractValidation:
    valid: bool
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "reason_codes": list(self.reason_codes)}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


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


def _missing_fields(payload: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    return [field for field in required if payload.get(field) in ("", None)]


def contains_secret_material(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered_key = str(key).lower()
            if any(marker in lowered_key for marker in SECRET_MARKERS):
                return True
            if contains_secret_material(item):
                return True
        return False
    if isinstance(value, list):
        return any(contains_secret_material(item) for item in value)
    return False


def validate_execution_request(request: dict[str, Any] | None) -> ContractValidation:
    reasons: list[str] = []
    if not isinstance(request, dict):
        return ContractValidation(False, ("EXEC_REQUEST_MISSING",))

    for field in _missing_fields(request, REQUIRED_REQUEST_FIELDS):
        reasons.append(f"EXEC_REQUEST_{field.upper()}_MISSING")

    capability = str(request.get("capability", ""))
    if request.get("schema") != EXECUTION_REQUEST_SCHEMA:
        reasons.append("EXEC_REQUEST_SCHEMA_INVALID")
    if not isinstance(request.get("parameters"), dict):
        reasons.append("EXEC_REQUEST_PARAMETERS_INVALID")
    elif contains_secret_material(request.get("parameters")):
        reasons.append("EXEC_REQUEST_PARAMETERS_SECRET_MATERIAL_BLOCKED")
    if not isinstance(request.get("requires_human_approval"), bool):
        reasons.append("EXEC_REQUEST_HUMAN_APPROVAL_FLAG_INVALID")
    if parse_timestamp(request.get("requested_at")) is None:
        reasons.append("EXEC_REQUEST_REQUESTED_AT_INVALID")
    if capability in BLOCKED_CAPABILITIES:
        reasons.append(f"EXEC_REQUEST_CAPABILITY_BLOCKED:{capability}")
    elif capability not in PREVIEW_CAPABILITIES:
        reasons.append(f"EXEC_REQUEST_CAPABILITY_UNKNOWN:{capability or 'MISSING'}")

    return ContractValidation(not reasons, tuple(sorted(set(reasons))))


def validate_execution_approval(
    approval: dict[str, Any] | None,
    *,
    request: dict[str, Any] | None,
    expected_scope: str = "PREVIEW_ONLY",
    pbsec_state: dict[str, Any] | None = None,
    now: datetime | None = None,
    max_age_hours: float = 24.0,
) -> ContractValidation:
    reasons: list[str] = []
    if not isinstance(approval, dict):
        return ContractValidation(False, ("EXEC_APPROVAL_MISSING",))
    if not isinstance(request, dict):
        return ContractValidation(False, ("EXEC_APPROVAL_REQUEST_MISSING",))

    for field in _missing_fields(approval, REQUIRED_APPROVAL_FIELDS):
        reasons.append(f"EXEC_APPROVAL_{field.upper()}_MISSING")

    approver_role = str(approval.get("approver_role", "")).strip()
    if approval.get("schema") != EXECUTION_APPROVAL_SCHEMA:
        reasons.append("EXEC_APPROVAL_SCHEMA_INVALID")
    if approval.get("request_id") != request.get("request_id"):
        reasons.append("EXEC_APPROVAL_REQUEST_MISMATCH")
    if not approver_role:
        reasons.append("EXEC_APPROVAL_APPROVER_EMPTY")
    if approver_role.lower() in AI_APPROVER_IDENTITIES:
        reasons.append("EXEC_APPROVAL_AI_APPROVER_BLOCKED")
    if approval.get("approved_by_human") is not True:
        reasons.append("EXEC_APPROVAL_HUMAN_REQUIRED")
    if approval.get("no_ai_auto_approval") is not True:
        reasons.append("EXEC_APPROVAL_AI_AUTO_APPROVAL_BLOCKED")
    if str(approval.get("approved_scope", "")) != expected_scope:
        reasons.append("EXEC_APPROVAL_SCOPE_MISMATCH")
    if str(approval.get("approved_scope", "")) not in PREVIEW_APPROVAL_SCOPES:
        reasons.append("EXEC_APPROVAL_SCOPE_NOT_PREVIEW_ONLY")
    if not str(approval.get("approval_signature_or_hash", "")).strip():
        reasons.append("EXEC_APPROVAL_SIGNATURE_OR_HASH_MISSING")

    approved_at = parse_timestamp(approval.get("approved_at"))
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if approved_at is None:
        reasons.append("EXEC_APPROVAL_APPROVED_AT_INVALID")
    else:
        age_hours = (effective_now - approved_at).total_seconds() / 3600
        if age_hours < 0 or age_hours > max_age_hours:
            reasons.append("EXEC_APPROVAL_EXPIRED")

    if _production_like(request) and not _pbsec_005_verified(pbsec_state):
        reasons.append("EXEC_APPROVAL_PRODUCTION_PBSEC005_NOT_VERIFIED")

    return ContractValidation(not reasons, tuple(sorted(set(reasons))))


def _production_like(request: dict[str, Any] | None) -> bool:
    if not isinstance(request, dict):
        return False
    haystack = canonical_json(
        {
            "capability": request.get("capability", ""),
            "target": request.get("target", ""),
            "parameters": request.get("parameters", {}),
            "risk_level": request.get("risk_level", ""),
        }
    ).lower()
    return any(marker in haystack for marker in ("prod", "production", "release", "deploy", "promote"))


def _pbsec_005_verified(pbsec_state: dict[str, Any] | None) -> bool:
    if not isinstance(pbsec_state, dict):
        return False
    gate = pbsec_state.get("PB-SEC-005")
    if isinstance(gate, dict):
        return gate.get("state") == "VERIFIED" or gate.get("decision") in {"VERIFIED", "APPROVED"}
    gates = pbsec_state.get("gates")
    if isinstance(gates, dict):
        gate = gates.get("PB-SEC-005")
        return isinstance(gate, dict) and gate.get("decision") in {"VERIFIED", "APPROVED"} and gate.get("fail_closed") is False
    return pbsec_state.get("production_release_approved") is True and pbsec_state.get("status") in {"APPROVED", "VERIFIED", "READY"}


def build_execution_audit_record(
    *,
    request: dict[str, Any] | None,
    decision: str,
    reason_codes: list[str] | tuple[str, ...],
    previous_audit_hash: str = "",
    generated_at: str,
    adapter_status: str = "EXECUTION_DISABLED",
) -> dict[str, Any]:
    safe_request = request if isinstance(request, dict) else {}
    record = {
        "schema": EXECUTION_AUDIT_SCHEMA,
        "event_id": "",
        "request_id": str(safe_request.get("request_id", "")),
        "proposal_id": str(safe_request.get("proposal_id", "")),
        "capability": str(safe_request.get("capability", "")),
        "decision": str(decision),
        "reason_codes": sorted({str(code) for code in reason_codes if code}),
        "runtime_state_hash": str(safe_request.get("runtime_state_hash", "")),
        "pbsec_state_hash": str(safe_request.get("pbsec_state_hash", "")),
        "vision_audit_hash": str(safe_request.get("vision_audit_hash", "")),
        "previous_audit_hash": str(previous_audit_hash),
        "audit_hash": "",
        "generated_at": str(generated_at),
        "adapter_status": str(adapter_status),
        "secrets_logged": False,
        "raw_payload_logged": False,
    }
    event_seed = {key: value for key, value in record.items() if key not in {"event_id", "audit_hash"}}
    record["event_id"] = sha256_json({"event": event_seed})
    record["audit_hash"] = sha256_json(record | {"audit_hash": ""})
    return record
