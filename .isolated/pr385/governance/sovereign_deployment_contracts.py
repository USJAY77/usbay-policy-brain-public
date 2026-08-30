from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


SOVEREIGN_DEPLOYMENT_SCHEMA = "usbay.sovereign.deployment.v1"
SOVEREIGN_NODE_SCHEMA = "usbay.sovereign.node.v1"
SOVEREIGN_CLUSTER_SCHEMA = "usbay.sovereign.cluster.v1"
SOVEREIGN_ENVIRONMENT_SCHEMA = "usbay.sovereign.environment.v1"
SOVEREIGN_DEPLOYMENT_POLICY_VERSION = "usbay.pb-sovereign-deployment.governed-sovereign-platform.v1"

ALLOWED_DEPLOYMENT_TYPES = frozenset(
    {"ON_PREM", "PRIVATE_CLOUD", "SOVEREIGN_CLOUD", "AIR_GAPPED", "OFFLINE_MESH"}
)
ALLOWED_DEPLOYMENT_STATUSES = frozenset({"READY", "REVIEW_REQUIRED", "BLOCKED"})
REQUIRED_SOVEREIGN_DEPLOYMENT_FIELDS = (
    "deployment_id",
    "tenant_id",
    "environment_id",
    "cluster_id",
    "node_id",
    "deployment_type",
    "sovereignty_level",
    "policy_hash",
    "audit_hash",
    "evidence_hash",
    "lineage_hash",
    "deployment_status",
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
class SovereignDeploymentValidation:
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


def canonical_sovereign_deployment_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "deployment_id": str(record.get("deployment_id", "")),
        "tenant_id": str(record.get("tenant_id", "")),
        "environment_id": str(record.get("environment_id", "")),
        "cluster_id": str(record.get("cluster_id", "")),
        "node_id": str(record.get("node_id", "")),
        "deployment_type": str(record.get("deployment_type", "")),
        "sovereignty_level": str(record.get("sovereignty_level", "")),
        "policy_hash": str(record.get("policy_hash", "")),
        "audit_hash": str(record.get("audit_hash", "")),
        "evidence_hash": str(record.get("evidence_hash", "")),
        "lineage_hash": str(record.get("lineage_hash", "")),
        "deployment_status": str(record.get("deployment_status", "")),
        "reason_codes": sorted(str(code) for code in record.get("reason_codes", []) if code),
        "created_at": str(record.get("created_at", "")),
        "fail_closed": record.get("fail_closed") is True,
    }


def compute_sovereign_deployment_hash(record: dict[str, Any]) -> str:
    return sha256_json(canonical_sovereign_deployment_payload(record))


def validate_sovereign_deployment(record: dict[str, Any] | None) -> SovereignDeploymentValidation:
    if not isinstance(record, dict):
        return SovereignDeploymentValidation(False, "BLOCKED", ("SOVEREIGN_DEPLOYMENT_MALFORMED",))
    reasons: list[str] = []
    if record.get("schema") != SOVEREIGN_DEPLOYMENT_SCHEMA:
        reasons.append("SOVEREIGN_DEPLOYMENT_SCHEMA_INVALID")
    for field in REQUIRED_SOVEREIGN_DEPLOYMENT_FIELDS:
        if record.get(field) in ("", None):
            reasons.append(f"SOVEREIGN_{field.upper()}_MISSING")
    deployment_type = str(record.get("deployment_type", ""))
    if deployment_type not in ALLOWED_DEPLOYMENT_TYPES:
        reasons.append(f"SOVEREIGN_DEPLOYMENT_TYPE_UNKNOWN:{deployment_type or 'MISSING'}")
    deployment_status = str(record.get("deployment_status", ""))
    if deployment_status not in ALLOWED_DEPLOYMENT_STATUSES:
        reasons.append(f"SOVEREIGN_DEPLOYMENT_STATUS_UNKNOWN:{deployment_status or 'MISSING'}")
    if parse_timestamp(record.get("created_at")) is None:
        reasons.append("SOVEREIGN_CREATED_AT_INVALID")
    if not isinstance(record.get("reason_codes"), list):
        reasons.append("SOVEREIGN_REASON_CODES_MALFORMED")
    if contains_sensitive_marker(record):
        reasons.append("SOVEREIGN_SENSITIVE_PAYLOAD_BLOCKED")
    if record.get("deployment_hash") and record.get("deployment_hash") != compute_sovereign_deployment_hash(record):
        return SovereignDeploymentValidation(False, "TAMPER_DETECTED", ("SOVEREIGN_DEPLOYMENT_HASH_MISMATCH",))
    status = "BLOCKED" if reasons else deployment_status
    return SovereignDeploymentValidation(not reasons and status == "READY", status, tuple(sorted(set(reasons))))


def build_sovereign_deployment_record(
    *,
    deployment_id: str,
    tenant_id: str,
    environment_id: str,
    cluster_id: str,
    node_id: str,
    deployment_type: str,
    sovereignty_level: str,
    policy_hash: str,
    audit_hash: str,
    evidence_hash: str,
    lineage_hash: str,
    deployment_status: str,
    created_at: str,
    reason_codes: list[str] | tuple[str, ...] = (),
    fail_closed: bool = True,
) -> dict[str, Any]:
    record = {
        "schema": SOVEREIGN_DEPLOYMENT_SCHEMA,
        "deployment_id": str(deployment_id),
        "tenant_id": str(tenant_id),
        "environment_id": str(environment_id),
        "cluster_id": str(cluster_id),
        "node_id": str(node_id),
        "deployment_type": str(deployment_type),
        "sovereignty_level": str(sovereignty_level),
        "policy_hash": str(policy_hash),
        "audit_hash": str(audit_hash),
        "evidence_hash": str(evidence_hash),
        "lineage_hash": str(lineage_hash),
        "deployment_status": str(deployment_status),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "created_at": str(created_at),
        "fail_closed": bool(fail_closed),
        "deployment_hash": "",
    }
    record["deployment_hash"] = compute_sovereign_deployment_hash(record)
    return record
