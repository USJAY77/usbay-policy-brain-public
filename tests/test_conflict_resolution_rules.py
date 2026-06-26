from __future__ import annotations

from synchronization.notion_euria_sync import DEFAULT_POLICY_HASH, conflict_resolution_rules_json, resolve_conflict


def test_conflict_rules_default_to_notion_source_of_truth() -> None:
    rules = conflict_resolution_rules_json()
    assert rules["source_of_truth"] == "Notion"
    assert rules["default_decision"] == "USE_NOTION"
    assert rules["external_resolution_calls_allowed"] is False


def test_conflict_rules_block_euria_to_notion_writes() -> None:
    result = resolve_conflict(direction="Euria -> Notion", policy_hash=DEFAULT_POLICY_HASH)
    assert result["decision"] == "BLOCKED"
    assert result["rule"] == "BLOCK_EURIA_WRITE"


def test_conflict_rules_use_notion_when_values_differ() -> None:
    result = resolve_conflict(direction="Notion -> Euria", policy_hash=DEFAULT_POLICY_HASH, values_match=False)
    assert result["decision"] == "READ_ONLY"
    assert result["source_of_truth"] == "Notion"


def test_conflict_rules_block_unknown_policy_hash() -> None:
    result = resolve_conflict(direction="Notion -> Euria", policy_hash="0" * 64)
    assert result["decision"] == "BLOCKED"
    assert result["rule"] == "REQUIRE_HUMAN_REVIEW"
