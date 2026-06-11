from control_plane.adapter_registry import AdapterRegistryDashboard
from control_plane.ui.adapter_registry_view import build_adapter_registry_view


def test_adapter_registry_ui_displays_adapter_states() -> None:
    registry = AdapterRegistryDashboard()
    registry.register("desktop", "REGISTERED", "READY_FOR_REVIEW", "desktop_ready")
    registry.register("browser", "DISABLED", "REVIEW_REQUIRED", "browser_disabled")
    registry.register("api", "BLOCKED", "FAIL_CLOSED", "api_blocked")

    view = build_adapter_registry_view(registry.dashboard())

    assert view.desktop_adapter_state == "REGISTERED"
    assert view.browser_adapter_state == "DISABLED"
    assert view.api_adapter_state == "BLOCKED"
    assert view.disabled_adapters == ("browser",)
    assert view.blocked_adapters == ("api",)
    assert view.readiness_state == "FAIL_CLOSED"


def test_adapter_registry_ui_fail_closed_when_adapter_missing() -> None:
    view = build_adapter_registry_view(
        {
            "registered_adapters": ["desktop"],
            "disabled_adapters": [],
            "blocked_adapters": [],
            "readiness_state": "READY_FOR_REVIEW",
            "all_records_audited": True,
        }
    )

    assert view.browser_adapter_state == "FAIL_CLOSED"
    assert view.api_adapter_state == "FAIL_CLOSED"
    assert view.readiness_state == "FAIL_CLOSED"


def test_adapter_registry_ui_fail_closed_when_audit_missing() -> None:
    view = build_adapter_registry_view(
        {
            "registered_adapters": ["desktop", "browser", "api"],
            "disabled_adapters": [],
            "blocked_adapters": [],
            "readiness_state": "READY_FOR_REVIEW",
            "all_records_audited": False,
        }
    )

    assert view.readiness_state == "FAIL_CLOSED"

