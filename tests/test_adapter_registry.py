from control_plane.adapter_registry import AdapterRegistryDashboard


def test_adapter_registry_dashboard_tracks_registered_disabled_and_blocked_adapters() -> None:
    registry = AdapterRegistryDashboard()
    registry.register("desktop", "REGISTERED", "READY_FOR_REVIEW", "desktop_contract_verified")
    registry.register("browser", "DISABLED", "REVIEW_REQUIRED", "browser_contract_mock_only")
    registry.register("api", "BLOCKED", "FAIL_CLOSED", "api_binding_missing")

    dashboard = registry.dashboard()

    assert dashboard["registered_adapters"] == ["desktop"]
    assert dashboard["disabled_adapters"] == ["browser"]
    assert dashboard["blocked_adapters"] == ["api"]
    assert dashboard["readiness_state"] == "FAIL_CLOSED"
    assert dashboard["all_records_audited"] is True


def test_adapter_registry_invalid_state_blocks_adapter() -> None:
    registry = AdapterRegistryDashboard()
    record = registry.register("robotic", "ENABLED", "READY", "invalid_state")

    assert record.state == "BLOCKED"
    assert record.readiness_state == "FAIL_CLOSED"
    assert record.reason == "adapter_state_invalid"

