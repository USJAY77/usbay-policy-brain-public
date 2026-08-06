---
name: Runtime commit pin
description: Why the sync badge's runtime SHA is pinned per process, not read live from git
---
Rule: `current_runtime_commit()` (governance/deployment_sync.py) pins its first successful resolution for the process lifetime; expected target env is still read per request.
**Why:** Replit auto-commits move workspace HEAD after startup; a per-request `git rev-parse HEAD` then redefines the "runtime" SHA and manufactures a false SYNC DRIFT in dev preview while the running process is unchanged. Production containers use the static stamp file, so behavior there is unchanged.
**How to apply:** never re-resolve the running artifact's commit live; a changed governed target must still surface drift (expected side stays per-request). Tests: tests/test_dashboard_drift_truth.py (pin lifetime, workspace-advance-stays-synced, changed-target-drifts). Reset hook `_reset_runtime_commit_pin_for_tests()` for tests.
