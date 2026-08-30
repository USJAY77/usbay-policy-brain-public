from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


TENANT_IDENTITY_SCHEMA = "usbay.tenant.identity.v1"
TENANT_POLICY_SCOPE_SCHEMA = "usbay.tenant.policy_scope.v1"
TENANT_EVIDENCE_SCOPE_SCHEMA = "usbay.tenant.evidence_scope.v1"
TENANT_AUDIT_SCOPE_SCHEMA = "usbay.tenant.audit_scope.v1"
TENANT_RELEASE_SCOPE_SCHEMA = "usbay.tenant.release_scope.v1"
TENANT_BOUNDARY_DECISION_SCHEMA = "usbay.tenant.boundary_decision.v1"
TENANT_BOUNDARY_POLICY_VERSION = "usbay.pb-tenant-boundary.governed-tenant-isolation.v1"

ALLOWED_TENANT_CLASSIFICATIONS = frozenset({"INTERNAL", "STARTER", "ENTERPRISE", "CRITICAL_INFRA", "SOVEREIGN"})
REQUIRED_TENANT_FIELDS = (
    "tenant_id",
    "tenant_name",
    "tenant_region",
    "tenant_classification",
    "policy_namespace",
    "evidence_namespace",
    "audit_namespace",
    "release_namespace",
    "document_namespace",
    "requested_by",
    "approved_by",
    "created_at",
    "policy_version",
    "policy_hash",
    "audit_hash",
    "boundary_hash",
    "decision",
    "reason_codes",
    "fail_closed",
)
SENSITIVE_MARKERS = ("secret", "token", "credential", "password", "api_key", "private_key", "cookie", "authorization", "payload")


@dataclass(frozen=True)
class TenantValidation:
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


def canonical_tenant_payload(tenant: dict[str, Any]) -> dict[str, Any]:
    return {
        "tenant_id": str(tenant.get("tenant_id", "")),
        "tenant_name": str(tenant.get("tenant_name", "")),
        "tenant_region": str(tenant.get("tenant_region", "")),
        "tenant_classification": str(tenant.get("tenant_classification", "")),
        "policy_namespace": str(tenant.get("policy_namespace", "")),
        "evidence_namespace": str(tenant.get("evidence_namespace", "")),
        "audit_namespace": str(tenant.get("audit_namespace", "")),
        "release_namespace": str(tenant.get("release_namespace", "")),
        "document_namespace": str(tenant.get("document_namespace", "")),
        "requested_by": str(tenant.get("requested_by", "")),
        "approved_by": str(tenant.get("approved_by", "")),
        "created_at": str(tenant.get("created_at", "")),
        "policy_version": str(tenant.get("policy_version", "")),
        "policy_hash": str(tenant.get("policy_hash", "")),
        "audit_hash": str(tenant.get("audit_hash", "")),
        "decision": str(tenant.get("decision", "")),
        "reason_codes": sorted(str(code) for code in tenant.get("reason_codes", []) if code),
        "fail_closed": tenant.get("fail_closed") is True,
    }


def compute_boundary_hash(tenant: dict[str, Any]) -> str:
    return sha256_json(canonical_tenant_payload(tenant))


def validate_tenant_identity(tenant: dict[str, Any] | None) -> TenantValidation:
    if not isinstance(tenant, dict):
        return TenantValidation(False, "BLOCKED", ("TENANT_IDENTITY_MALFORMED",))
    reasons: list[str] = []
    if tenant.get("schema") != TENANT_IDENTITY_SCHEMA:
        reasons.append("TENANT_IDENTITY_SCHEMA_INVALID")
    for field in REQUIRED_TENANT_FIELDS:
        if tenant.get(field) in ("", None):
            if field == "approved_by" and tenant.get("decision") in {"REVIEW_REQUIRED", "BLOCKED"}:
                continue
            reasons.append(f"TENANT_{field.upper()}_MISSING")
    classification = str(tenant.get("tenant_classification", ""))
    if classification not in ALLOWED_TENANT_CLASSIFICATIONS:
        reasons.append(f"TENANT_CLASSIFICATION_UNKNOWN:{classification or 'MISSING'}")
    if tenant.get("tenant_id") in {"*", "global", "GLOBAL", "default", "DEFAULT"}:
        reasons.append("TENANT_IMPLICIT_OR_WILDCARD_BLOCKED")
    if parse_timestamp(tenant.get("created_at")) is None:
        reasons.append("TENANT_CREATED_AT_INVALID")
    if not isinstance(tenant.get("reason_codes"), list):
        reasons.append("TENANT_REASON_CODES_MALFORMED")
    if contains_sensitive_marker(tenant):
        reasons.append("TENANT_SENSITIVE_PAYLOAD_BLOCKED")
    if tenant.get("boundary_hash") and tenant.get("boundary_hash") != compute_boundary_hash(tenant):
        return TenantValidation(False, "TAMPER_DETECTED", ("TENANT_BOUNDARY_HASH_MISMATCH",))
    return TenantValidation(not reasons, "BLOCKED" if reasons else "VERIFIED", tuple(sorted(set(reasons))))


def build_tenant_identity(
    *,
    tenant_id: str,
    tenant_name: str,
    tenant_region: str,
    tenant_classification: str,
    policy_namespace: str,
    evidence_namespace: str,
    audit_namespace: str,
    release_namespace: str,
    document_namespace: str,
    requested_by: str,
    approved_by: str = "",
    created_at: str,
    policy_version: str = TENANT_BOUNDARY_POLICY_VERSION,
    policy_hash: str,
    audit_hash: str,
    decision: str = "REVIEW_REQUIRED",
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = True,
) -> dict[str, Any]:
    tenant = {
        "schema": TENANT_IDENTITY_SCHEMA,
        "tenant_id": str(tenant_id),
        "tenant_name": str(tenant_name),
        "tenant_region": str(tenant_region),
        "tenant_classification": str(tenant_classification),
        "policy_namespace": str(policy_namespace),
        "evidence_namespace": str(evidence_namespace),
        "audit_namespace": str(audit_namespace),
        "release_namespace": str(release_namespace),
        "document_namespace": str(document_namespace),
        "requested_by": str(requested_by),
        "approved_by": str(approved_by),
        "created_at": str(created_at),
        "policy_version": str(policy_version),
        "policy_hash": str(policy_hash),
        "audit_hash": str(audit_hash),
        "boundary_hash": "",
        "decision": str(decision),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "fail_closed": bool(fail_closed),
    }
    tenant["boundary_hash"] = compute_boundary_hash(tenant)
    return tenant
