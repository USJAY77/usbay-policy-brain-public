# PB-166 Runtime Hardening Reconstruction Plan

Decision: VERIFIED
Status: READY_FOR_REVIEW

## Input Findings
PB-164 proved source drift: `runtime/governance-runtime-hardening` is behind current `main`, and direct Wave 2 extraction would delete or regress current gateway, demo, and test content.

PB-165 segmented 49 unique source commits:
- `DEMO_REDESIGN_REQUIRED`: 9
- `GATEWAY_REDESIGN_REQUIRED`: 1
- `SAFE_DELETE_CANDIDATE`: 7
- `UNKNOWN_REVIEW_REQUIRED`: 5
- `WAVE_4_TEST_SUPPORT`: 25
- `WAVE_5_DOCS_ONLY`: 2

PB-165 found no independently safe `WAVE_3_SAFE_RUNTIME_ONLY` package.

## Survival Decision
- KEEP: current policy validator, enforcement gateway primitives, audit schemas/logger, security guard primitives.
- REBUILD: runtime controller, decision engine, risk classifier, execution contract, vision provider layer, rollback layer, redesigned gateway adapter.
- REPLACE: stale source-branch gateway/demo deltas and implicit runtime coupling.
- REMOVE: safe-delete candidates and stale documentation/demo/evidence artifacts only after separate human review.

## PB-167 Through PB-171 Roadmap
See `runtime_phase_plan.json` for full dependencies, risks, and validation strategies.

## Obsolete Components
- Dead code: source-branch artifacts absent from current main and marked `SAFE_DELETE_CANDIDATE`.
- Legacy demo artifacts: source-branch demo/evidence packages blocked by drift.
- Duplicated tests: source-branch test support not tied to a safe runtime package.
- Obsolete gateway logic: direct `gateway/app.py` source drift.
- Obsolete runtime logic: stale hardening commits requiring redesign.

## Governance Outcome
No source-branch code is extracted. The next safe path is a current-main-first reconstruction program, starting with PB-167.
