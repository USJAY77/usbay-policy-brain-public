from __future__ import annotations

from typing import Any


NAMESPACE_FIELDS = (
    "policy_namespace",
    "evidence_namespace",
    "audit_namespace",
    "release_namespace",
    "document_namespace",
    "connector_namespace",
    "operator_namespace",
)
FORBIDDEN_TENANT_IDS = {"*", "global", "GLOBAL", "default", "DEFAULT"}


def build_namespace_registry(tenants: list[dict[str, Any]] | None) -> dict[str, Any]:
    entries = [tenant for tenant in tenants or [] if isinstance(tenant, dict)]
    namespace_owners: dict[str, str] = {}
    reasons: list[str] = []
    for tenant in entries:
        tenant_id = str(tenant.get("tenant_id", ""))
        if tenant_id in FORBIDDEN_TENANT_IDS or not tenant_id:
            reasons.append("TENANT_IMPLICIT_OR_WILDCARD_BLOCKED")
        for field in NAMESPACE_FIELDS:
            namespace = str(tenant.get(field, ""))
            if not namespace:
                reasons.append(f"BLOCKED_WITH_MISSING_NAMESPACE:{field}")
                continue
            existing = namespace_owners.get(namespace)
            if existing and existing != tenant_id:
                reasons.append(f"BLOCKED_WITH_TENANT_MISMATCH:{namespace}")
            namespace_owners[namespace] = tenant_id
    return {
        "tenant_namespace_status": "BLOCKED" if reasons else ("READY" if entries else "BLOCKED"),
        "tenants": entries,
        "namespace_owners": namespace_owners,
        "reason_codes": sorted(set(reasons)) or ([] if entries else ["TENANT_NAMESPACE_REGISTRY_EMPTY"]),
        "shared_default_tenant": False,
        "implicit_global_tenant": False,
        "fallback_namespace": False,
        "wildcard_tenant_access": False,
        "cross_tenant_inheritance": False,
        "copy_enabled": False,
        "move_enabled": False,
        "sync_enabled": False,
        "export_enabled": False,
    }


def resolve_namespace(registry: dict[str, Any] | None, *, tenant_id: str, namespace: str) -> tuple[str, tuple[str, ...]]:
    if not isinstance(registry, dict):
        return "BLOCKED", ("TENANT_NAMESPACE_REGISTRY_MISSING",)
    if tenant_id in FORBIDDEN_TENANT_IDS or not tenant_id:
        return "BLOCKED", ("TENANT_IMPLICIT_OR_WILDCARD_BLOCKED",)
    if not namespace:
        return "BLOCKED", ("BLOCKED_WITH_MISSING_NAMESPACE",)
    owner = registry.get("namespace_owners", {}).get(namespace)
    if not owner:
        return "BLOCKED", ("BLOCKED_WITH_MISSING_NAMESPACE",)
    if owner != tenant_id:
        return "BLOCKED", ("BLOCKED_WITH_TENANT_MISMATCH",)
    return "ALLOWED_WITHIN_TENANT", ()
