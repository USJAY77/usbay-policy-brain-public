from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def tenant_view_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TenantDashboardUIView:
    tenant_registry_state: str
    tenant_policy_binding_state: str
    tenant_audit_separation_state: str
    tenant_readiness_state: str
    tenant_count: int
    audit_hash: str


def build_tenant_dashboard_view(isolation_report: dict[str, object] | None) -> TenantDashboardUIView:
    if isolation_report is None:
        return _view("FAIL_CLOSED", "FAIL_CLOSED", "FAIL_CLOSED", "FAIL_CLOSED", 0)
    tenant_count = int(isolation_report.get("tenant_count", 0))
    registry_state = "VERIFIED" if tenant_count > 0 and isolation_report.get("all_records_audited") is True else "FAIL_CLOSED"
    policy_state = str(isolation_report.get("tenant_policy_binding", "FAIL_CLOSED"))
    audit_state = str(isolation_report.get("tenant_audit_separation", "FAIL_CLOSED"))
    readiness = "READY_FOR_REVIEW" if registry_state == policy_state == audit_state == "VERIFIED" else "FAIL_CLOSED"
    return _view(registry_state, policy_state, audit_state, readiness, tenant_count)


def _view(registry: str, policy: str, audit: str, readiness: str, tenant_count: int) -> TenantDashboardUIView:
    return TenantDashboardUIView(
        tenant_registry_state=registry,
        tenant_policy_binding_state=policy,
        tenant_audit_separation_state=audit,
        tenant_readiness_state=readiness,
        tenant_count=tenant_count,
        audit_hash=tenant_view_hash(registry, policy, audit, readiness, tenant_count),
    )

