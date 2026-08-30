1. Purpose
- Adds a read-only Notion-Euria governance synchronization layer before any live automation.
- Treats Notion as source of truth and Euria as governed consumer only.

2. Governance Impact
- Adds mapping registry, synchronization validation, conflict resolution rules, evidence synchronization contract, and local pilot sync report.
- Blocks Euria -> Notion writes, live connector calls, browser automation, desktop automation, and external API calls.

3. Risk Assessment
- If source-of-truth rules are wrong, Euria could overwrite Notion governance state.
- If sync direction is wrong, live write-back could create silent governance drift.
- If evidence sync calls external systems, read-only pilot evidence could be contaminated by live state.
- If policy hashes are unknown, synchronization must block pending human review.

4. Validation Evidence
- `python3 -m py_compile synchronization/notion_euria_sync.py`
- `python3 -m json.tool governance/evidence/pb231_235/notion_euria_mapping_registry.json`
- `python3 -m json.tool governance/evidence/pb231_235/sync_validation_report.json`
- `python3 -m json.tool governance/evidence/pb231_235/conflict_resolution_rules.json`
- `python3 -m json.tool governance/evidence/pb231_235/evidence_sync_contract.json`
- `python3 -m json.tool governance/evidence/pb231_235/validation_results.json`
- `pytest -q tests/test_notion_euria_mapping_registry.py tests/test_sync_validation_engine.py tests/test_conflict_resolution_rules.py tests/test_evidence_sync_contract.py tests/test_read_only_pilot_sync.py`
- `git diff --check`
- `rg -n "^(<<<<<<<|=======|>>>>>>>)" synchronization/notion_euria_sync.py tests/test_notion_euria_mapping_registry.py tests/test_sync_validation_engine.py tests/test_conflict_resolution_rules.py tests/test_evidence_sync_contract.py tests/test_read_only_pilot_sync.py governance/evidence/pb231_235`

5. Fail-Closed Check
- Default sync states are `READ_ONLY` or `BLOCKED`.
- Euria -> Notion writes are blocked.
- Live connector calls, browser automation, desktop automation, and external API calls are blocked.
- Unknown policy hashes block synchronization pending human review.

6. Human Approval Required
- Human review is required before merge.
- Separate explicit approval is required before Notion-Euria live sync.
- No live synchronization or connector activation is included.
