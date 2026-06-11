from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from control_plane.tenant_policy import TenantPolicyBinding


def tenant_registry_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TenantRecord:
    tenant_id: str
    display_name: str
    policy_binding: TenantPolicyBinding
    audit_namespace: str
    audit_hash: str


class TenantRegistry:
    def __init__(self) -> None:
        self._tenants: dict[str, TenantRecord] = {}

    def register(self, tenant_id: str, display_name: str, policy_binding: TenantPolicyBinding) -> tuple[bool, str]:
        if not tenant_id:
            return False, "tenant_id_missing"
        if tenant_id in self._tenants:
            return False, "tenant_duplicate"
        if policy_binding.decision != "ALLOW":
            return False, "tenant_policy_binding_invalid"
        record = TenantRecord(
            tenant_id=tenant_id,
            display_name=display_name,
            policy_binding=policy_binding,
            audit_namespace=policy_binding.audit_namespace,
            audit_hash=tenant_registry_hash(tenant_id, display_name, policy_binding.audit_hash),
        )
        self._tenants[tenant_id] = record
        return True, "tenant_registered"

    def validate_isolation(self) -> dict[str, object]:
        namespaces = [record.audit_namespace for record in self._tenants.values()]
        isolated = len(namespaces) == len(set(namespaces))
        return {
            "tenant_count": len(self._tenants),
            "tenant_isolation": "VERIFIED" if isolated else "FAIL_CLOSED",
            "tenant_policy_binding": "VERIFIED"
            if all(record.policy_binding.decision == "ALLOW" for record in self._tenants.values())
            else "FAIL_CLOSED",
            "tenant_audit_separation": "VERIFIED" if isolated else "FAIL_CLOSED",
            "all_records_audited": all(bool(record.audit_hash) for record in self._tenants.values()),
        }

