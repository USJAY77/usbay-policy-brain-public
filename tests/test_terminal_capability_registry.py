from __future__ import annotations

from terminal.command_governance import ALLOWED_COMMAND_CLASSES, terminal_capability_registry_json


def test_terminal_capability_registry_defines_allowed_read_only_classes() -> None:
    registry = terminal_capability_registry_json()
    assert registry["allowed_command_classes"] == list(ALLOWED_COMMAND_CLASSES)
    assert registry["external_api_calls_allowed"] is False
    assert registry["sensitive_output_storage_allowed"] is False


def test_terminal_capability_registry_blocks_write_merge_push_delete_install_network_and_secret_reading() -> None:
    registry = terminal_capability_registry_json()
    assert registry["write_commands_default"] == "BLOCKED"
    assert registry["merge_commands_default"] == "BLOCKED"
    assert registry["push_commands_default"] == "BLOCKED"
    assert registry["delete_commands_default"] == "BLOCKED"
    assert registry["install_commands_default"] == "BLOCKED"
    assert registry["network_commands_default"] == "BLOCKED"
    assert registry["secret_reading_commands_default"] == "BLOCKED"
