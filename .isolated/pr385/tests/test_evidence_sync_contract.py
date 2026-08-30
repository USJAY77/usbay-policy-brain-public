from __future__ import annotations

from synchronization.notion_euria_sync import evidence_sync_contract_json


def test_evidence_sync_contract_is_local_only_and_blocks_writes() -> None:
    contract = evidence_sync_contract_json()
    assert contract["local_evidence_only"] is True
    assert contract["notion_writes_allowed"] is False
    assert contract["euria_writes_allowed"] is False
    assert contract["github_writes_allowed"] is False
    assert contract["codex_actions_allowed"] is False


def test_evidence_sync_contract_blocks_browser_desktop_and_external_api() -> None:
    contract = evidence_sync_contract_json()
    assert contract["browser_automation_allowed"] is False
    assert contract["desktop_automation_allowed"] is False
    assert contract["external_api_calls_allowed"] is False
    assert "read_only_pilot_sync_report.md" in contract["required_artifacts"]
