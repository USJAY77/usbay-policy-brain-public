from control_plane.tenant_policy import bind_tenant_policy
from control_plane.tenant_registry import TenantRegistry
from control_plane.ui.tenant_dashboard_view import build_tenant_dashboard_view


def test_tenant_dashboard_ui_displays_verified_tenant_readiness() -> None:
    registry = TenantRegistry()
    binding = bind_tenant_policy("tenant-a", "policy-v1", "tenant-a/audit")
    registry.register("tenant-a", "Tenant A", binding)

    view = build_tenant_dashboard_view(registry.validate_isolation())

    assert view.tenant_registry_state == "VERIFIED"
    assert view.tenant_policy_binding_state == "VERIFIED"
    assert view.tenant_audit_separation_state == "VERIFIED"
    assert view.tenant_readiness_state == "READY_FOR_REVIEW"
    assert view.tenant_count == 1
    assert view.audit_hash


def test_tenant_dashboard_ui_fail_closed_without_tenant_records() -> None:
    view = build_tenant_dashboard_view(
        {
            "tenant_count": 0,
            "tenant_isolation": "VERIFIED",
            "tenant_policy_binding": "VERIFIED",
            "tenant_audit_separation": "VERIFIED",
            "all_records_audited": True,
        }
    )

    assert view.tenant_registry_state == "FAIL_CLOSED"
    assert view.tenant_readiness_state == "FAIL_CLOSED"


def test_tenant_dashboard_ui_fail_closed_on_missing_report() -> None:
    view = build_tenant_dashboard_view(None)

    assert view.tenant_registry_state == "FAIL_CLOSED"
    assert view.tenant_readiness_state == "FAIL_CLOSED"

