from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


DOCUMENT_IDENTITY_SCHEMA = "usbay.document.identity.v1"
DOCUMENT_VERSION_SCHEMA = "usbay.document.version.v1"
DOCUMENT_CLASSIFICATION_SCHEMA = "usbay.document.classification.v1"
DOCUMENT_LIFECYCLE_SCHEMA = "usbay.document.lifecycle.v1"
DOCUMENT_LINEAGE_SCHEMA = "usbay.document.lineage.v1"
DOCUMENT_REVIEW_SCHEMA = "usbay.document.review.v1"
DOCUMENT_GOVERNANCE_POLICY_VERSION = "usbay.pb-document-governance.governed-document-lifecycle.v1"

ALLOWED_DOCUMENT_CLASSIFICATIONS = frozenset({"PUBLIC", "INTERNAL", "CONFIDENTIAL", "REGULATED", "CRITICAL"})
ALLOWED_DOCUMENT_TYPES = frozenset(
    {
        "POLICY",
        "STANDARD",
        "PROCEDURE",
        "ROADMAP",
        "TARIFF_CARD",
        "CONTRACT",
        "APPENDIX",
        "GOVERNANCE_REPORT",
        "EVIDENCE_REPORT",
    }
)
REQUIRED_DOCUMENT_FIELDS = (
    "document_id",
    "document_title",
    "document_type",
    "document_classification",
    "document_owner",
    "tenant_id",
    "version",
    "status",
    "created_at",
    "updated_at",
    "policy_version",
    "policy_hash",
    "audit_hash",
    "lineage_hash",
    "document_hash",
    "reason_codes",
    "fail_closed",
)
SENSITIVE_MARKERS = ("secret", "token", "credential", "password", "api_key", "private_key", "cookie", "authorization", "raw_payload")


@dataclass(frozen=True)
class DocumentValidation:
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
    text = str(value).lower()
    if isinstance(value, dict):
        text = " ".join(str(item).lower() for pair in value.items() for item in pair)
    elif isinstance(value, list):
        text = " ".join(str(item).lower() for item in value)
    return any(marker in text for marker in SENSITIVE_MARKERS)


def canonical_document_payload(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "document_id": str(document.get("document_id", "")),
        "document_title": str(document.get("document_title", "")),
        "document_type": str(document.get("document_type", "")),
        "document_classification": str(document.get("document_classification", "")),
        "document_owner": str(document.get("document_owner", "")),
        "tenant_id": str(document.get("tenant_id", "")),
        "version": str(document.get("version", "")),
        "status": str(document.get("status", "")),
        "created_at": str(document.get("created_at", "")),
        "updated_at": str(document.get("updated_at", "")),
        "policy_version": str(document.get("policy_version", "")),
        "policy_hash": str(document.get("policy_hash", "")),
        "audit_hash": str(document.get("audit_hash", "")),
        "lineage_hash": str(document.get("lineage_hash", "")),
        "reason_codes": sorted(str(code) for code in document.get("reason_codes", []) if code),
        "fail_closed": document.get("fail_closed") is True,
    }


def compute_document_hash(document: dict[str, Any]) -> str:
    return sha256_json(canonical_document_payload(document))


def validate_document(document: dict[str, Any] | None) -> DocumentValidation:
    if not isinstance(document, dict):
        return DocumentValidation(False, "BLOCKED", ("DOCUMENT_MALFORMED",))
    reasons: list[str] = []
    if document.get("schema") != DOCUMENT_IDENTITY_SCHEMA:
        reasons.append("DOCUMENT_SCHEMA_INVALID")
    for field in REQUIRED_DOCUMENT_FIELDS:
        if document.get(field) in ("", None):
            reasons.append(f"DOCUMENT_{field.upper()}_MISSING")
    classification = str(document.get("document_classification", ""))
    if classification not in ALLOWED_DOCUMENT_CLASSIFICATIONS:
        reasons.append(f"DOCUMENT_CLASSIFICATION_UNKNOWN:{classification or 'MISSING'}")
    document_type = str(document.get("document_type", ""))
    if document_type not in ALLOWED_DOCUMENT_TYPES:
        reasons.append(f"DOCUMENT_TYPE_UNKNOWN:{document_type or 'MISSING'}")
    if parse_timestamp(document.get("created_at")) is None:
        reasons.append("DOCUMENT_CREATED_AT_INVALID")
    if parse_timestamp(document.get("updated_at")) is None:
        reasons.append("DOCUMENT_UPDATED_AT_INVALID")
    if not isinstance(document.get("reason_codes"), list):
        reasons.append("DOCUMENT_REASON_CODES_MALFORMED")
    if contains_sensitive_marker(document):
        reasons.append("DOCUMENT_SENSITIVE_PAYLOAD_BLOCKED")
    if document.get("document_hash") and document.get("document_hash") != compute_document_hash(document):
        return DocumentValidation(False, "TAMPER_DETECTED", ("DOCUMENT_HASH_MISMATCH",))
    return DocumentValidation(not reasons, "BLOCKED" if reasons else "VALID", tuple(sorted(set(reasons))))


def build_document(
    *,
    document_id: str,
    document_title: str,
    document_type: str,
    document_classification: str,
    document_owner: str,
    tenant_id: str,
    version: str,
    status: str,
    created_at: str,
    updated_at: str,
    policy_version: str = DOCUMENT_GOVERNANCE_POLICY_VERSION,
    policy_hash: str,
    audit_hash: str,
    lineage_hash: str,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = True,
) -> dict[str, Any]:
    document = {
        "schema": DOCUMENT_IDENTITY_SCHEMA,
        "document_id": str(document_id),
        "document_title": str(document_title),
        "document_type": str(document_type),
        "document_classification": str(document_classification),
        "document_owner": str(document_owner),
        "tenant_id": str(tenant_id),
        "version": str(version),
        "status": str(status),
        "created_at": str(created_at),
        "updated_at": str(updated_at),
        "policy_version": str(policy_version),
        "policy_hash": str(policy_hash),
        "audit_hash": str(audit_hash),
        "lineage_hash": str(lineage_hash),
        "document_hash": "",
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "fail_closed": bool(fail_closed),
    }
    document["document_hash"] = compute_document_hash(document)
    return document
