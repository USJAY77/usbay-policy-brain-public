from __future__ import annotations

from pathlib import Path

from synchronization.notion_euria_sync import read_only_sync_report_json


REPORT = Path("governance/evidence/pb231_235/read_only_pilot_sync_report.md")


def test_read_only_pilot_sync_report_blocks_live_automation() -> None:
    text = REPORT.read_text(encoding="utf-8")
    assert "Notion is source of truth" in text
    assert "Euria is governed consumer only" in text
    assert "Euria -> Notion writes are BLOCKED" in text
    assert "No external API calls" in text


def test_read_only_sync_report_json_is_local_only() -> None:
    report = read_only_sync_report_json()
    assert report["decision"] == "VERIFIED"
    assert report["status"] == "READ_ONLY"
    assert report["live_connector_calls_performed"] is False
    assert report["browser_automation_performed"] is False
    assert report["desktop_automation_performed"] is False
    assert report["external_api_calls_performed"] is False
