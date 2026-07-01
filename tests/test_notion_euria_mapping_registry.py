from __future__ import annotations

from synchronization.notion_euria_sync import mapping_registry_json, validate_sync_registry


def test_mapping_registry_treats_notion_as_source_and_euria_as_consumer() -> None:
    registry = mapping_registry_json()
    assert registry["source_of_truth"] == "Notion"
    assert registry["consumer"] == "Euria"
    assert registry["write_back_allowed"] is False
    assert registry["default_sync_state"] == "READ_ONLY"


def test_mapping_registry_contains_required_mapping_fields() -> None:
    mapping = mapping_registry_json()["mappings"][0]
    for field in (
        "notion_section",
        "euria_project",
        "usbay_control_plane_category",
        "allowed_sync_direction",
        "blocked_sync_direction",
        "evidence_path",
        "policy_hash",
    ):
        assert field in mapping
    assert mapping["allowed_sync_direction"] == "Notion -> Euria"
    assert mapping["blocked_sync_direction"] == "Euria -> Notion"


def test_mapping_registry_validation_passes_read_only_contract() -> None:
    result = validate_sync_registry(mapping_registry_json())
    assert result["decision"] == "VERIFIED"
    assert result["status"] == "READ_ONLY"
    assert result["local_evidence_only"] is True
