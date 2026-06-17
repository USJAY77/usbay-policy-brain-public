from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


CONNECTOR_REGISTRY_SCHEMA = "usbay.connector.registry.v1"
CONNECTOR_SOURCE_SCHEMA = "usbay.connector.source.v1"
CONNECTOR_READ_REQUEST_SCHEMA = "usbay.connector.read_request.v1"
CONNECTOR_READ_RESULT_SCHEMA = "usbay.connector.read_result.v1"
CONNECTOR_AUDIT_RECORD_SCHEMA = "usbay.connector.audit_record.v1"
CONNECTOR_POLICY_VERSION = "usbay.pb-integration.governed-enterprise-connector.v1"

ALLOWED_CONNECTOR_TYPES = frozenset({"GITHUB", "JIRA", "SERVICENOW", "SLACK", "EMAIL", "CALENDAR", "DOCUMENT_REPOSITORY"})
ALLOWED_READ_ACTIONS = frozenset(
    {
        "READ_METADATA",
        "READ_STATUS",
        "READ_COMMENTS",
        "READ_EVENTS",
        "READ_DOCUMENT_SUMMARY",
        "READ_AUDIT_REFERENCE",
        "READ_REPOSITORY_STATE",
        "READ_ISSUE_STATE",
        "READ_TICKET_STATE",
        "READ_MESSAGE_METADATA",
        "READ_CALENDAR_BUSY_FREE",
    }
)
BLOCKED_WRITE_ACTIONS = frozenset(
    {
        "CREATE",
        "UPDATE",
        "DELETE",
        "SEND_MESSAGE",
        "SEND_EMAIL",
        "INVITE_USER",
        "MERGE_PR",
        "PUSH_CODE",
        "DEPLOY",
        "TRIGGER_WORKFLOW",
        "CREATE_TICKET",
        "UPDATE_TICKET",
        "CLOSE_TICKET",
        "DOWNLOAD_SECRET",
        "READ_SECRET",
        "LOGIN",
        "PAYMENT",
        "BROWSER_CLICK",
        "SHELL_EXECUTION",
    }
)
SENSITIVE_MARKERS = ("secret", "token", "credential", "password", "authorization", "api_key", "private_key", "cookie")

REQUIRED_CONNECTOR_FIELDS = (
    "connector_id",
    "connector_type",
    "source_system",
    "requested_by",
    "requested_at",
    "read_scope",
    "policy_version",
    "audit_hash",
    "lineage_hash",
    "fail_closed",
    "reason_codes",
)


@dataclass(frozen=True)
class ConnectorValidation:
    valid: bool
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "reason_codes": list(self.reason_codes)}


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


def missing_fields(payload: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    return [field for field in required if payload.get(field) in ("", None)]


def contains_sensitive_marker(value: Any) -> bool:
    text = str(value).lower()
    if isinstance(value, dict):
        text = " ".join(str(item).lower() for pair in value.items() for item in pair)
    elif isinstance(value, list):
        text = " ".join(str(item).lower() for item in value)
    return any(marker in text for marker in SENSITIVE_MARKERS)


def validate_read_request(request: dict[str, Any] | None) -> ConnectorValidation:
    if not isinstance(request, dict):
        return ConnectorValidation(False, ("CONNECTOR_REQUEST_MALFORMED",))
    reasons: list[str] = []
    for field in missing_fields(request, REQUIRED_CONNECTOR_FIELDS):
        reasons.append(f"CONNECTOR_{field.upper()}_MISSING")
    if request.get("schema") != CONNECTOR_READ_REQUEST_SCHEMA:
        reasons.append("CONNECTOR_REQUEST_SCHEMA_INVALID")
    connector_type = str(request.get("connector_type", ""))
    if connector_type not in ALLOWED_CONNECTOR_TYPES:
        reasons.append(f"CONNECTOR_TYPE_UNKNOWN:{connector_type or 'MISSING'}")
    action = str(request.get("read_scope", ""))
    if action in BLOCKED_WRITE_ACTIONS:
        reasons.append(f"CONNECTOR_WRITE_ACTION_BLOCKED:{action}")
    elif action not in ALLOWED_READ_ACTIONS:
        reasons.append(f"CONNECTOR_READ_SCOPE_UNKNOWN:{action or 'MISSING'}")
    if parse_timestamp(request.get("requested_at")) is None:
        reasons.append("CONNECTOR_REQUESTED_AT_INVALID")
    if contains_sensitive_marker(request.get("read_scope", "")) or contains_sensitive_marker(request.get("parameters", {})):
        reasons.append("CONNECTOR_SECRET_OR_CREDENTIAL_REQUEST_BLOCKED")
    if not str(request.get("audit_hash", "")).strip():
        reasons.append("CONNECTOR_AUDIT_HASH_MISSING")
    if not str(request.get("lineage_hash", "")).strip():
        reasons.append("CONNECTOR_LINEAGE_HASH_MISSING")
    if not str(request.get("policy_version", "")).strip():
        reasons.append("CONNECTOR_POLICY_VERSION_MISSING")
    return ConnectorValidation(not reasons, tuple(sorted(set(reasons))))


def validate_read_result(result: dict[str, Any] | None) -> ConnectorValidation:
    if not isinstance(result, dict):
        return ConnectorValidation(False, ("CONNECTOR_RESULT_MALFORMED",))
    reasons: list[str] = []
    required = REQUIRED_CONNECTOR_FIELDS + ("evidence_manifest_id", "result_hash", "redacted_summary")
    for field in missing_fields(result, required):
        reasons.append(f"CONNECTOR_RESULT_{field.upper()}_MISSING")
    if result.get("schema") != CONNECTOR_READ_RESULT_SCHEMA:
        reasons.append("CONNECTOR_RESULT_SCHEMA_INVALID")
    if contains_sensitive_marker(result.get("redacted_summary", "")) or contains_sensitive_marker(result.get("raw_payload", "")):
        reasons.append("CONNECTOR_RESULT_SENSITIVE_DATA_BLOCKED")
    if result.get("raw_payload") not in ("", None):
        reasons.append("CONNECTOR_RESULT_RAW_PAYLOAD_BLOCKED")
    return ConnectorValidation(not reasons, tuple(sorted(set(reasons))))


def build_connector_audit_record(*, request: dict[str, Any] | None, decision: str, reason_codes: list[str] | tuple[str, ...], generated_at: str) -> dict[str, Any]:
    safe = request if isinstance(request, dict) else {}
    record = {
        "schema": CONNECTOR_AUDIT_RECORD_SCHEMA,
        "connector_id": str(safe.get("connector_id", "")),
        "connector_type": str(safe.get("connector_type", "")),
        "source_system": str(safe.get("source_system", "")),
        "requested_by_hash": sha256_json(str(safe.get("requested_by", ""))) if safe.get("requested_by") else "",
        "read_scope": str(safe.get("read_scope", "")),
        "decision": str(decision),
        "reason_codes": sorted({str(code) for code in reason_codes if code}),
        "generated_at": str(generated_at),
        "policy_version": str(safe.get("policy_version", CONNECTOR_POLICY_VERSION)),
        "audit_hash": "",
        "raw_payload_logged": False,
        "secrets_logged": False,
        "tokens_logged": False,
        "write_enabled": False,
        "auto_authorized": False,
    }
    record["audit_hash"] = sha256_json(record | {"audit_hash": ""})
    return record
