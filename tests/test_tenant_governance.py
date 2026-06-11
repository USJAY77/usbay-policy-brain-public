from control_plane.tenant_policy import bind_tenant_policy
from control_plane.tenant_registry import TenantRegistry


def test_tenant_policy_binding_requires_tenant_scoped_audit_namespace() -> None:
    binding = bind_tenant_policy("tenant-a", "policy-v1", "tenant-a/audit")

    assert binding.decision == "ALLOW"
    assert binding.reason == "tenant_policy_bound"
    assert binding.audit_hash


def test_tenant_policy_binding_fail_closed_on_namespace_mismatch() -> None:
    binding = bind_tenant_policy("tenant-a", "policy-v1", "tenant-b/audit")

    assert binding.decision == "FAIL_CLOSED"
    assert binding.reason == "tenant_audit_namespace_mismatch"


def test_tenant_registry_validates_isolation_and_audit_separation() -> None:
    registry = TenantRegistry()
    binding_a = bind_tenant_policy("tenant-a", "policy-v1", "tenant-a/audit")
    binding_b = bind_tenant_policy("tenant-b", "policy-v1", "tenant-b/audit")

    assert registry.register("tenant-a", "Tenant A", binding_a) == (True, "tenant_registered")
    assert registry.register("tenant-b", "Tenant B", binding_b) == (True, "tenant_registered")

    isolation = registry.validate_isolation()

    assert isolation["tenant_isolation"] == "VERIFIED"
    assert isolation["tenant_policy_binding"] == "VERIFIED"
    assert isolation["tenant_audit_separation"] == "VERIFIED"
    assert isolation["all_records_audited"] is True


def test_tenant_registry_blocks_invalid_policy_binding() -> None:
    registry = TenantRegistry()
    binding = bind_tenant_policy("tenant-a", None, "tenant-a/audit")

    assert registry.register("tenant-a", "Tenant A", binding) == (False, "tenant_policy_binding_invalid")

