from __future__ import annotations

from typing import Any


def _approved(value: Any) -> bool:
    if isinstance(value, dict):
        return value.get("approved") is True or value.get("status") in {"READY", "APPROVED"}
    return str(value) in {"READY", "APPROVED"}


def evaluate_production_release_prerequisites(
    *,
    approved_release_gate: dict[str, Any] | str | None,
    approved_audit_registry: dict[str, Any] | str | None,
    approved_evidence_registry: dict[str, Any] | str | None,
    approved_tenant_boundary: dict[str, Any] | str | None,
    approved_document_governance: dict[str, Any] | str | None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not _approved(approved_release_gate):
        reasons.append("PRODUCTION_RELEASE_GATE_NOT_APPROVED")
    if not _approved(approved_audit_registry):
        reasons.append("PRODUCTION_AUDIT_REGISTRY_NOT_APPROVED")
    if not _approved(approved_evidence_registry):
        reasons.append("PRODUCTION_EVIDENCE_REGISTRY_NOT_APPROVED")
    if not _approved(approved_tenant_boundary):
        reasons.append("PRODUCTION_TENANT_BOUNDARY_NOT_APPROVED")
    if not _approved(approved_document_governance):
        reasons.append("PRODUCTION_DOCUMENT_GOVERNANCE_NOT_APPROVED")
    status = "READY" if not reasons else "BLOCKED"
    return {
        "schema": "usbay.production.release_readiness.v1",
        "release_readiness_status": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status != "READY",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "auto_deploy": False,
        "auto_release": False,
        "auto_rollback": False,
        "auto_recover": False,
        "auto_remediate": False,
    }


def evaluate_release_readiness(
    *,
    human_approval: dict[str, Any] | None,
    policy_registry_status: str,
    audit_registry_status: str,
    evidence_trust_status: str,
    test_summary_hash: str,
    rollback_plan_hash: str,
    tenant_boundary_status: str,
    production_readiness_status: str,
    release_manifest_hash: str,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not isinstance(human_approval, dict) or human_approval.get("approved") is not True:
        reasons.append("RELEASE_HUMAN_APPROVAL_MISSING")
    if str(policy_registry_status) != "ACTIVE":
        reasons.append("RELEASE_POLICY_REGISTRY_NOT_ACTIVE")
    if str(audit_registry_status) != "READY":
        reasons.append("RELEASE_AUDIT_REGISTRY_NOT_READY")
    if str(evidence_trust_status) != "READY":
        reasons.append("RELEASE_EVIDENCE_TRUST_NOT_READY")
    if not str(test_summary_hash).strip():
        reasons.append("RELEASE_TEST_SUMMARY_MISSING")
    if not str(rollback_plan_hash).strip():
        reasons.append("RELEASE_ROLLBACK_PLAN_MISSING")
    if not str(tenant_boundary_status).strip() or str(tenant_boundary_status) == "NOT_IMPLEMENTED":
        reasons.append("BLOCKED_WITH_MISSING_TENANT_BOUNDARY")
    elif str(tenant_boundary_status) != "READY":
        reasons.append("RELEASE_TENANT_BOUNDARY_NOT_READY")
    if not str(production_readiness_status).strip() or str(production_readiness_status) == "NOT_IMPLEMENTED":
        reasons.append("BLOCKED_WITH_MISSING_PRODUCTION_READINESS")
    elif str(production_readiness_status) != "READY":
        reasons.append("RELEASE_PRODUCTION_READINESS_NOT_READY")
    if not str(release_manifest_hash).strip():
        reasons.append("RELEASE_MANIFEST_HASH_MISSING")
    return {
        "schema": "usbay.release.readiness.v1",
        "release_readiness_status": "BLOCKED" if reasons else "READY",
        "reason_codes": sorted(set(reasons)),
        "fail_closed": bool(reasons),
        "rollback_plan_status": "PRESENT" if str(rollback_plan_hash).strip() else "MISSING",
        "tenant_boundary_status": str(tenant_boundary_status or "MISSING"),
        "production_readiness_status": str(production_readiness_status or "MISSING"),
        "auto_deployed": False,
        "auto_released": False,
        "auto_rolled_back": False,
        "auto_promoted": False,
    }
