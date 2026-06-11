from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def tenant_policy_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TenantPolicyBinding:
    tenant_id: str
    policy_version: str
    audit_namespace: str
    decision: str
    reason: str
    audit_hash: str


def bind_tenant_policy(tenant_id: str | None, policy_version: str | None, audit_namespace: str | None) -> TenantPolicyBinding:
    if not tenant_id:
        decision = "FAIL_CLOSED"
        reason = "tenant_id_missing"
    elif not policy_version:
        decision = "FAIL_CLOSED"
        reason = "policy_version_missing"
    elif not audit_namespace:
        decision = "FAIL_CLOSED"
        reason = "audit_namespace_missing"
    elif tenant_id not in audit_namespace:
        decision = "FAIL_CLOSED"
        reason = "tenant_audit_namespace_mismatch"
    else:
        decision = "ALLOW"
        reason = "tenant_policy_bound"
    return TenantPolicyBinding(
        tenant_id=tenant_id or "",
        policy_version=policy_version or "",
        audit_namespace=audit_namespace or "",
        decision=decision,
        reason=reason,
        audit_hash=tenant_policy_hash(tenant_id, policy_version, audit_namespace, decision, reason),
    )

