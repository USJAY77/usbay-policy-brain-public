from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


DEFAULT_TENANT_POLICY_PATH = Path("governance/tenant_policy.json")
TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class TenantIsolationError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def tenant_hash(tenant_id: str) -> str:
    return hashlib.sha256(str(tenant_id).encode("utf-8")).hexdigest()


def load_tenant_policy(path: Path | str = DEFAULT_TENANT_POLICY_PATH) -> dict[str, Any]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise TenantIsolationError("tenant_policy_invalid:unreadable") from exc
    if not isinstance(raw, dict):
        raise TenantIsolationError("tenant_policy_invalid:root")
    allowed = raw.get("allowed_tenant_ids")
    if not isinstance(allowed, list) or not allowed:
        raise TenantIsolationError("tenant_policy_invalid:allowed_tenant_ids")
    tenants = []
    for tenant_id in allowed:
        if not isinstance(tenant_id, str) or not TENANT_ID_RE.fullmatch(tenant_id):
            raise TenantIsolationError("tenant_policy_invalid:allowed_tenant_ids")
        tenants.append(tenant_id)
    if raw.get("tenant_evidence_isolation") is not True:
        raise TenantIsolationError("tenant_policy_invalid:tenant_evidence_isolation")
    export_permissions = raw.get("tenant_export_permissions")
    if not isinstance(export_permissions, dict):
        raise TenantIsolationError("tenant_policy_invalid:tenant_export_permissions")
    for tenant_id in tenants:
        if tenant_id not in export_permissions or export_permissions[tenant_id] is not True:
            raise TenantIsolationError("tenant_policy_invalid:tenant_export_permissions")
    retention = raw.get("tenant_retention_policy")
    if not isinstance(retention, dict):
        raise TenantIsolationError("tenant_policy_invalid:tenant_retention_policy")
    for tenant_id in tenants:
        tenant_retention = retention.get(tenant_id)
        if not isinstance(tenant_retention, dict):
            raise TenantIsolationError("tenant_policy_invalid:tenant_retention_policy")
        try:
            days = int(tenant_retention.get("retention_days"))
        except Exception as exc:
            raise TenantIsolationError("tenant_policy_invalid:tenant_retention_policy") from exc
        if days <= 0:
            raise TenantIsolationError("tenant_policy_invalid:tenant_retention_policy")
    return {
        "allowed_tenant_ids": tenants,
        "tenant_retention_policy": retention,
        "tenant_evidence_isolation": True,
        "tenant_export_permissions": export_permissions,
    }


def validate_tenant_id(tenant_id: Any, policy_path: Path | str = DEFAULT_TENANT_POLICY_PATH) -> str:
    if not isinstance(tenant_id, str) or not tenant_id or not TENANT_ID_RE.fullmatch(tenant_id):
        raise TenantIsolationError("tenant_context_missing")
    policy = load_tenant_policy(policy_path)
    if tenant_id not in policy["allowed_tenant_ids"]:
        raise TenantIsolationError("tenant_not_allowed")
    return tenant_id


def tenant_execution_context(tenant_id: Any, policy_path: Path | str = DEFAULT_TENANT_POLICY_PATH) -> dict[str, str]:
    validated = validate_tenant_id(tenant_id, policy_path)
    return {
        "tenant_id": validated,
        "tenant_hash": tenant_hash(validated),
        "tenant_scope": f"tenant/{validated}",
    }


def tenant_scoped_path(root: Path | str, tenant_id: Any) -> Path:
    context = tenant_execution_context(tenant_id)
    return Path(root) / context["tenant_scope"]


def assert_same_tenant(actual: Any, expected: str) -> None:
    if str(actual or "") != str(expected):
        raise TenantIsolationError("tenant_mismatch_detected")


def extract_record_tenant(record: dict[str, Any]) -> str:
    tenant_id = record.get("tenant_id")
    if isinstance(record.get("decision"), dict):
        tenant_id = record["decision"].get("tenant_id", tenant_id)
    return validate_tenant_id(tenant_id)


def validate_consensus_tenant(evidence: dict[str, Any], expected_tenant_id: str) -> None:
    if not isinstance(evidence, dict):
        raise TenantIsolationError("foreign_consensus_evidence")
    assert_same_tenant(evidence.get("tenant_id"), expected_tenant_id)
    for node in evidence.get("nodes", []):
        if isinstance(node, dict):
            assert_same_tenant(node.get("tenant_id"), expected_tenant_id)
    for attestation in evidence.get("attestation_evidence", []):
        if isinstance(attestation, dict):
            assert_same_tenant(attestation.get("tenant_id"), expected_tenant_id)
    provenance = evidence.get("deployment_provenance")
    if isinstance(provenance, dict) and provenance.get("tenant_id"):
        assert_same_tenant(provenance.get("tenant_id"), expected_tenant_id)


def validate_records_single_tenant(records: list[dict[str, Any]], expected_tenant_id: str | None = None) -> str:
    if not records:
        raise TenantIsolationError("tenant_context_missing")
    tenants = {extract_record_tenant(record) for record in records}
    if len(tenants) != 1:
        raise TenantIsolationError("cross_tenant_evidence_reference")
    tenant_id = next(iter(tenants))
    if expected_tenant_id is not None:
        assert_same_tenant(tenant_id, expected_tenant_id)
    for record in records:
        decision = record.get("decision") if isinstance(record.get("decision"), dict) else {}
        evidence = decision.get("consensus_evidence_bundle") if isinstance(decision, dict) else None
        if evidence:
            validate_consensus_tenant(evidence, tenant_id)
    return tenant_id
