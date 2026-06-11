# PB-164 Runtime Hardening Source Drift Root Cause Analysis

Decision: VERIFIED
Status: READY_FOR_REVIEW

## Root Cause
PB-163 produced `BLOCKED_SOURCE_DRIFT_DETECTED` because `runtime/governance-runtime-hardening` is behind current `main`. The next PB-161 Wave 2 candidate set is no longer a clean additive extraction. A direct source-branch delta would remove or rewrite current-main runtime, demo, and test content.

## Exact Wave 2 Blocker Evidence
- `gateway/app.py`: source delta against main has 187 additions and 1297 deletions.
- `demo/governance_demo_flow.py`: source delta against main has 0 additions and 158 deletions.
- `demo/templates/governance_demo_flow.html`: source delta against main has 0 additions and 14 deletions.
- `tests/test_governance_demo_flow.py`: source delta against main has 0 additions and 49 deletions.

## Commit Drift
- Source-unique commits observed by Git: 50
- Main-unique commits observed by Git: 55
- Patch-equivalent commits already in main by `git cherry`: 0
- Commits partially represented by exact subject match only: 1
- Commits unique to source by available Git evidence: 49
- Commits with unknown classification: 0

## File Drift
- Files classified: 588
- Classification counts: `{'ALREADY_IN_MAIN': 92, 'PARTIALLY_IN_MAIN': 9, 'UNIQUE_RUNTIME_DELTA': 9, 'DOCUMENTATION_ONLY': 182, 'SAFE_DELETE_CANDIDATE': 43, 'BLOCKED': 253}`

## Wave Planning
- Wave 3 candidates are recorded in `extraction_recommendations.json` and should be evaluated separately after excluding already-in-main files.
- Wave 4 candidates are documentation/evidence reconciliation items and must not be mixed with runtime extraction.
- Never Extract candidates are all `BLOCKED` entries in `file_drift_map.json`.
- Requires Redesign candidates include `gateway/app.py`, `demo/governance_demo_flow.py`, `demo/templates/governance_demo_flow.html`, and `tests/test_governance_demo_flow.py`.

## Audit
- No extraction performed.
- No merge performed.
- No deploy performed.
- No delete performed.
- No branch cleanup performed.
- No runtime mutation performed.
- No external API calls performed.
- No credentials created.
