from __future__ import annotations

from runtime.computer_use.vision_governance import ALLOWED_LOCAL_CAPABILITIES, EXECUTION_CAPABILITIES, vision_capability_registry_json


def test_vision_capability_registry_allows_only_local_metadata_capabilities() -> None:
    registry = vision_capability_registry_json()
    assert set(registry["local_only_capabilities"]) == set(ALLOWED_LOCAL_CAPABILITIES)
    assert all(item["state"] == "LOCAL_ONLY" for item in registry["local_only_capabilities"].values())
    assert all(item["external_api_calls_allowed"] is False for item in registry["local_only_capabilities"].values())


def test_vision_execution_capabilities_default_disabled() -> None:
    registry = vision_capability_registry_json()
    assert set(registry["execution_capabilities"]) == set(EXECUTION_CAPABILITIES)
    assert all(item["state"] == "DISABLED" for item in registry["execution_capabilities"].values())
    assert registry["browser_execution_allowed"] is False
    assert registry["desktop_execution_allowed"] is False
    assert registry["external_api_calls_allowed"] is False
    assert registry["raw_screenshot_storage_allowed"] is False
