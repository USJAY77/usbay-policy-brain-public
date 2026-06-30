from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


DOCUMENT_LIBRARY_SCHEMA = "usbay.document_library.record.v1"
DOCUMENT_LIBRARY_INDEX_SCHEMA = "usbay.document_library.index.v1"
DOCUMENT_LIBRARY_REVIEW_SCHEMA = "usbay.document_library.review.v1"
DOCUMENT_LIBRARY_POLICY_VERSION = "usbay.pb-document-library.governed-document-library.v1"

ALLOWED_DOCUMENT_LIBRARY_STATES = frozenset(
    {"DRAFT", "INDEXED", "REVIEW_REQUIRED", "APPROVED", "ACTIVE", "SUPERSEDED", "SUSPENDED", "ARCHIVED", "BLOCKED"}
)
FAIL_CLOSED_REASON_CODES = frozenset(
    {
        "UNKNOWN_DOCUMENT_LIBRARY",
        "MISSING_WORKSPACE",
        "MISSING_TENANT",
        "MISSING_POLICY",
        "MISSING_AUDIT",
        "MISSING_EVIDENCE",
        "MISSING_DOCUMENT_HASH",
        "MISSING_LINEAGE",
        "DUPLICATE_WITHOUT_VERSION",
        "CROSS_TENANT_LIBRARY_ACCESS",
        "SHARED_DEFAULT_LIBRARY_FORBIDDEN",
        "NO_HUMAN_APPROVAL",
        "AUTO_CLASSIFICATION_FORBIDDEN",
        "AUTO_REWRITE_FORBIDDEN",
        "AUTO_PUBLISH_FORBIDDEN",
        "AUTO_DELETE_FORBIDDEN",
        "CONNECTOR_WRITE_FORBIDDEN",
        "RAW_PAYLOAD_LOGGING_FORBIDDEN",
        "SENSITIVE_DATA_RETENTION_FORBIDDEN",
    }
)
REQUIRED_DOCUMENT_LIBRARY_FIELDS = (
    "library_id",
    "workspace_id",
    "tenant_id",
    "document_id",
    "document_version",
    "library_state",
    "policy_hash",
    "audit_hash",
    "evidence_hash",
    "document_hash",
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
    "credential",
    "raw_payload",
    "raw_screenshot",
    "screenshot",
)


@dataclass(frozen=True)
class DocumentLibraryValidation:
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


def canonical_document_library_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "library_id": str(record.get("library_id", "")),
        "workspace_id": str(record.get("workspace_id", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "document_id": str(record.get("document_id", "")),
        "document_version": str(record.get("document_version", "")),
        "library_state": str(record.get("library_state", "")),
        "policy_hash": str(record.get("policy_hash", "")),
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "document_hash": str(record.get("document_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "human_approval": record.get("human_approval") is True,
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "created_at": str(record.get("created_at", "")),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_document_library_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_document_library_payload(record))


def validate_document_library(record: dict[str, Any] | None) -> DocumentLibraryValidation:
    if not isinstance(record, dict):
        return DocumentLibraryValidation(False, "BLOCKED", ("UNKNOWN_DOCUMENT_LIBRARY",))
    reasons: list[str] = []
    if record.get("schema") != DOCUMENT_LIBRARY_SCHEMA:
        reasons.append("UNKNOWN_DOCUMENT_LIBRARY")
    for field in REQUIRED_DOCUMENT_LIBRARY_FIELDS:
        if record.get(field) in ("", None):
            reasons.append(f"DOCUMENT_LIBRARY_{field.upper()}_MISSING")
    if not str(record.get("workspace_id", "")).strip():
        reasons.append("MISSING_WORKSPACE")
    if not str(record.get("tenant_id", "")).strip():
        reasons.append("MISSING_TENANT")
    if not str(record.get("policy_hash", "")).strip():
        reasons.append("MISSING_POLICY")
    if not str(record.get("audit_hash", "")).strip():
        reasons.append("MISSING_AUDIT")
    if not str(record.get("evidence_hash", "")).strip():
        reasons.append("MISSING_EVIDENCE")
    if not str(record.get("document_hash", "")).strip():
        reasons.append("MISSING_DOCUMENT_HASH")
    if not str(record.get("lineage_hash", "")).strip():
        reasons.append("MISSING_LINEAGE")
    state = str(record.get("library_state", ""))
    if state not in ALLOWED_DOCUMENT_LIBRARY_STATES:
        reasons.append(f"DOCUMENT_LIBRARY_STATE_UNKNOWN:{state or 'MISSING'}")
    if record.get("human_approval") is not True:
        reasons.append("NO_HUMAN_APPROVAL")
    if record.get("auto_classification") is True:
        reasons.append("AUTO_CLASSIFICATION_FORBIDDEN")
    if record.get("auto_rewrite") is True:
        reasons.append("AUTO_REWRITE_FORBIDDEN")
    if record.get("auto_publish") is True:
        reasons.append("AUTO_PUBLISH_FORBIDDEN")
    if record.get("auto_delete") is True:
        reasons.append("AUTO_DELETE_FORBIDDEN")
    if record.get("connector_write") is True:
        reasons.append("CONNECTOR_WRITE_FORBIDDEN")
    if record.get("raw_payload_logging") is True:
        reasons.append("RAW_PAYLOAD_LOGGING_FORBIDDEN")
    if record.get("sensitive_data_retention") is True or contains_sensitive_marker(record):
        reasons.append("SENSITIVE_DATA_RETENTION_FORBIDDEN")
    if parse_timestamp(record.get("created_at")) is None:
        reasons.append("DOCUMENT_LIBRARY_CREATED_AT_INVALID")
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("DOCUMENT_LIBRARY_REASON_CODES_MALFORMED")
    if record.get("library_hash") and record.get("library_hash") != compute_document_library_hash(record):
        return DocumentLibraryValidation(False, "TAMPER_DETECTED", ("DOCUMENT_LIBRARY_HASH_MISMATCH",))
    status = "BLOCKED" if reasons else state
    return DocumentLibraryValidation(not reasons and status in {"APPROVED", "ACTIVE", "INDEXED"}, status, tuple(sorted(set(reasons))))


def build_document_library_record(
    *,
    library_id: str,
    workspace_id: str,
    tenant_id: str,
    document_id: str,
    document_version: str,
    library_state: str,
    policy_hash: str,
    audit_hash: str,
    evidence_hash: str,
    document_hash: str,
    lineage_hash: str,
    human_approval: bool,
    created_at: str,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = True,
) -> dict[str, Any]:
    record = {
        "schema": DOCUMENT_LIBRARY_SCHEMA,
        "library_id": str(library_id),
        "workspace_id": str(workspace_id),
        "tenant_id": str(tenant_id),
        "document_id": str(document_id),
        "document_version": str(document_version),
        "library_state": str(library_state),
        "policy_hash": str(policy_hash),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "document_hash": str(document_hash),
        "lineage_hash": str(lineage_hash),
        "human_approval": bool(human_approval),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "created_at": str(created_at),
        "fail_closed": bool(fail_closed),
        "library_hash": "",
    }
    record["library_hash"] = compute_document_library_hash(record)
    return record
