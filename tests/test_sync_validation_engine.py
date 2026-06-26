from __future__ import annotations

from synchronization.notion_euria_sync import mapping_registry_json, validate_sync_registry


def test_sync_validation_blocks_euria_to_notion_write_enablement() -> None:
    registry = mapping_registry_json()
    registry["write_back_allowed"] = True
    result = validate_sync_registry(registry)
    assert result["decision"] == "FAIL_CLOSED"
    assert "WRITE_BACK_ALLOWED_MUST_BE_FALSE" in result["gaps"]


def test_sync_validation_blocks_live_connector_calls() -> None:
    registry = mapping_registry_json()
    registry["live_connector_calls_allowed"] = True
    result = validate_sync_registry(registry)
    assert result["decision"] == "FAIL_CLOSED"
    assert "LIVE_CONNECTOR_CALLS_ALLOWED_MUST_BE_FALSE" in result["gaps"]


def test_sync_validation_blocks_browser_desktop_and_external_api_calls() -> None:
    registry = mapping_registry_json()
    registry["browser_automation_allowed"] = True
    registry["desktop_automation_allowed"] = True
    registry["external_api_calls_allowed"] = True
    result = validate_sync_registry(registry)
    assert result["decision"] == "FAIL_CLOSED"
    assert "BROWSER_AUTOMATION_ALLOWED_MUST_BE_FALSE" in result["gaps"]
    assert "DESKTOP_AUTOMATION_ALLOWED_MUST_BE_FALSE" in result["gaps"]
    assert "EXTERNAL_API_CALLS_ALLOWED_MUST_BE_FALSE" in result["gaps"]


def test_sync_validation_blocks_unknown_policy_hash() -> None:
    registry = mapping_registry_json()
    registry["mappings"][0]["policy_hash"] = "0" * 64
    result = validate_sync_registry(registry)
    assert result["decision"] == "FAIL_CLOSED"
    assert "UNKNOWN_POLICY_HASH" in result["gaps"]
