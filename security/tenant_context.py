from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


DEFAULT_TENANT_POLICY_PATH = Path("governance/tenant_policy.json")
TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
CANONICAL_TENANT_AUTHORITY_MODULE = "security.tenant_context"
TENANT_AUTHORITY_FIXTURE_ENV = "USBAY_TENANT_AUTHORITY_FIXTURE_PATH"
REASON_TENANT_AUTHORITY_FIXTURE_INVALID = "TENANT_AUTHORITY_FIXTURE_INVALID"
REASON_TENANT_AUTHORITY_MISMATCH = "TENANT_AUTHORITY_MISMATCH"
REASON_CROSS_TENANT_EXECUTION_BLOCKED = "CROSS_TENANT_EXECUTION_BLOCKED"


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


def tenant_authority_inventory() -> dict[str, Any]:
    return {
        "canonical_owner_module": CANONICAL_TENANT_AUTHORITY_MODULE,
        "canonical_owner_reason": "request, runtime authority, audit, evidence, and execution tenant checks resolve here",
        "ownership_points": [
            {
                "module": "security.tenant_context",
                "role": "aggregate_owner",
                "surface": "tenant validation, tenant hashing, tenant-scoped paths, runtime tenant consistency",
            },
            {
                "module": "governance.tenant_boundary",
                "role": "provider",
                "surface": "tenant boundary governance decisions and dashboard-safe state",
            },
            {
                "module": "governance.tenant_namespace_registry",
                "role": "provider",
                "surface": "tenant namespace ownership and mismatch detection",
            },
            {
                "module": "security.deployment_attestation",
                "role": "provider",
                "surface": "runtime release authority tenant identity",
            },
            {
                "module": "gateway.app",
                "role": "enforcement_consumer",
                "surface": "decision and execute fail-closed enforcement",
            },
            {
                "module": "audit.immutable_ledger",
                "role": "provider",
                "surface": "tenant-scoped append-only evidence export validation",
            },
        ],
        "duplicate_aggregate_owners": [],
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
    }


def canonical_tenant_authority_decision(
    *,
    request_tenant_id: Any,
    runtime_tenant_id: Any,
    decision_tenant_id: Any | None = None,
    policy_path: Path | str = DEFAULT_TENANT_POLICY_PATH,
) -> dict[str, Any]:
    reasons: list[str] = []
    try:
        request_tenant = validate_tenant_id(request_tenant_id, policy_path)
    except TenantIsolationError as exc:
        request_tenant = ""
        reasons.append(str(exc))
    try:
        runtime_tenant = validate_tenant_id(runtime_tenant_id, policy_path)
    except TenantIsolationError as exc:
        runtime_tenant = ""
        reasons.append(str(exc))
    decision_tenant = ""
    if decision_tenant_id is not None:
        try:
            decision_tenant = validate_tenant_id(decision_tenant_id, policy_path)
        except TenantIsolationError as exc:
            reasons.append(str(exc))
    if request_tenant and runtime_tenant and request_tenant != runtime_tenant:
        reasons.extend([REASON_TENANT_AUTHORITY_MISMATCH, REASON_CROSS_TENANT_EXECUTION_BLOCKED])
    if decision_tenant and request_tenant and decision_tenant != request_tenant:
        reasons.extend([REASON_TENANT_AUTHORITY_MISMATCH, REASON_CROSS_TENANT_EXECUTION_BLOCKED])
    if decision_tenant and runtime_tenant and decision_tenant != runtime_tenant:
        reasons.extend([REASON_TENANT_AUTHORITY_MISMATCH, REASON_CROSS_TENANT_EXECUTION_BLOCKED])
    status = "VALID" if not reasons else "BLOCKED"
    return {
        "tenant_authority_status": status,
        "canonical_owner_module": CANONICAL_TENANT_AUTHORITY_MODULE,
        "request_tenant_id": request_tenant,
        "request_tenant_hash": tenant_hash(request_tenant) if request_tenant else "",
        "runtime_tenant_id": runtime_tenant,
        "runtime_tenant_hash": tenant_hash(runtime_tenant) if runtime_tenant else "",
        "decision_tenant_id": decision_tenant,
        "decision_tenant_hash": tenant_hash(decision_tenant) if decision_tenant else "",
        "reason_codes": sorted(set(reason for reason in reasons if reason)),
        "fail_closed": status != "VALID",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


def _load_tenant_authority_fixture(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise TenantIsolationError(REASON_TENANT_AUTHORITY_FIXTURE_INVALID) from exc
    if not isinstance(payload, dict):
        raise TenantIsolationError(REASON_TENANT_AUTHORITY_FIXTURE_INVALID)
    return payload


def tenant_authority_readiness_report(
    *,
    fixture_path: str | Path | None = None,
    policy_path: Path | str = DEFAULT_TENANT_POLICY_PATH,
) -> dict[str, Any]:
    configured_path = fixture_path or os.getenv(TENANT_AUTHORITY_FIXTURE_ENV, "")
    if not configured_path:
        return {
            "tenant_authority_status": "VALID",
            "tenant_authority_configured": False,
            "canonical_owner_module": CANONICAL_TENANT_AUTHORITY_MODULE,
            "reason_codes": [],
            "read_only": True,
            "execution_enabled": False,
        }
    try:
        fixture = _load_tenant_authority_fixture(Path(configured_path))
        decision = canonical_tenant_authority_decision(
            request_tenant_id=fixture.get("request_tenant_id"),
            runtime_tenant_id=fixture.get("runtime_tenant_id"),
            decision_tenant_id=fixture.get("decision_tenant_id"),
            policy_path=policy_path,
        )
    except TenantIsolationError as exc:
        decision = {
            "tenant_authority_status": "BLOCKED",
            "canonical_owner_module": CANONICAL_TENANT_AUTHORITY_MODULE,
            "reason_codes": [str(exc)],
            "fail_closed": True,
            "read_only": True,
            "execution_enabled": False,
        }
    return {
        **decision,
        "tenant_authority_configured": True,
        "fixture_path": str(configured_path),
    }


def tenant_isolation_audit_evidence(
    *,
    fixture_path: str | Path | None = None,
    policy_path: Path | str = DEFAULT_TENANT_POLICY_PATH,
) -> dict[str, Any]:
    readiness = tenant_authority_readiness_report(fixture_path=fixture_path, policy_path=policy_path)
    return {
        "schema": "usbay.tenant.isolation_audit_evidence.v1",
        "canonical_authority": CANONICAL_TENANT_AUTHORITY_MODULE,
        "inventory": tenant_authority_inventory(),
        "readiness": readiness,
        "tenant_isolation_status": readiness["tenant_authority_status"],
        "fail_closed": readiness["tenant_authority_status"] != "VALID",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
    }
