# PB-148 Runtime Extraction Reduction Matrix

Decision: VERIFIED

Status: REVIEW_READY

Merge Readiness: FAIL_CLOSED_NOT_MERGE_READY

## Purpose

Reduce the 84 runtime extraction candidates from `runtime_branch_consolidation_matrix.json` into an actionable, fail-closed runtime extraction list. This is review-only evidence.

## Classification Counts

- `PARTIALLY_IN_MAIN`: 34
- `RUNTIME_UNIQUE`: 50

## Capability Family Counts

- `branch_release_governance`: 1
- `evidence_integrity_chain`: 45
- `runtime_governance_core`: 38

## Estimated Backlog Reduction

- Raw runtime extraction branches: `84`
- Reduced execution units: `3`
- Estimated reduction: `96.43%`

## Top 20 Highest-Value Runtime Branches

1. `usbay/runtime-branch-hygiene-divergence` - PARTIALLY_IN_MAIN - runtime_governance_core - score 114
2. `usbay/allowed-branch-policy-audit` - PARTIALLY_IN_MAIN - runtime_governance_core - score 100
3. `usbay/branch-policy-alignment` - PARTIALLY_IN_MAIN - runtime_governance_core - score 100
4. `governance/rfc3161-timestamp-policy-scaffold` - RUNTIME_UNIQUE - evidence_integrity_chain - score 96
5. `usbay/intake-gateway-phase-1-governance` - RUNTIME_UNIQUE - runtime_governance_core - score 96
6. `usbay/evidence-backlog-sync` - PARTIALLY_IN_MAIN - runtime_governance_core - score 95
7. `runtime/governance-runtime-hardening` - RUNTIME_UNIQUE - runtime_governance_core - score 91
8. `usbay/branch-hygiene-decision-correction` - PARTIALLY_IN_MAIN - runtime_governance_core - score 89
9. `usbay/branch-hygiene-terminal-state-correction` - PARTIALLY_IN_MAIN - runtime_governance_core - score 89
10. `usbay/architecture-certification-evidence-gaps` - PARTIALLY_IN_MAIN - runtime_governance_core - score 85
11. `runtime-policy-validator` - RUNTIME_UNIQUE - runtime_governance_core - score 81
12. `usbay/euria-live-assessment-workflow` - PARTIALLY_IN_MAIN - runtime_governance_core - score 78
13. `usbay/governance-metadata-authority` - PARTIALLY_IN_MAIN - runtime_governance_core - score 78
14. `governance/action-policy-registry` - RUNTIME_UNIQUE - evidence_integrity_chain - score 76
15. `governance/actions-policy-approval-chain` - RUNTIME_UNIQUE - evidence_integrity_chain - score 76
16. `governance/actions-policy-manifest` - RUNTIME_UNIQUE - evidence_integrity_chain - score 76
17. `usbay/cross-system-automation-orchestrator` - PARTIALLY_IN_MAIN - runtime_governance_core - score 75
18. `usbay/delete-branch-decision-trace` - PARTIALLY_IN_MAIN - runtime_governance_core - score 75
19. `usbay/governance-improvement-planning` - PARTIALLY_IN_MAIN - evidence_integrity_chain - score 75
20. `usbay/governance-maturity-assessment` - PARTIALLY_IN_MAIN - evidence_integrity_chain - score 75

## Top Safe-Delete Branches

No branch inside the 84 runtime extraction candidates is classified safe-delete. PB-148 therefore keeps the runtime extraction set fail-closed.

Supporting safe-delete candidates from the broader input matrix:
1. `ci-policy-verification` - SAFE_TO_DELETE_BRANCH
2. `governance/deterministic-review-semantics` - SAFE_TO_DELETE_BRANCH
3. `governance/investigate-pr71-production-readiness` - SAFE_TO_DELETE_BRANCH
4. `governance/mcp-governance-gateway` - SAFE_TO_DELETE_BRANCH
5. `governance/scope-aware-automerge-classification` - SAFE_TO_DELETE_BRANCH
6. `runtime/local-dev-recovery` - SAFE_TO_DELETE_BRANCH
7. `test/codex-trigger` - SAFE_TO_DELETE_BRANCH
8. `usbay/governance-evidence-freshness` - SAFE_TO_DELETE_BRANCH
9. `usbay/verify-live-pilot-outside-replit` - SAFE_TO_DELETE_BRANCH

## Dependency Map

1. `runtime_governance_core` - 38 branches - depends on: none
2. `evidence_integrity_chain` - 45 branches - depends on: runtime_governance_core
5. `branch_release_governance` - 1 branches - depends on: runtime_governance_core

## Duplication Report

- Duplicate runtime files detected: `34`
- Runtime branches should be reduced by extracting file/capability deltas instead of merging historical branches directly.

## Fail Closed

PB-148 does not authorize merge, delete, push, runtime mutation, external API calls, credential creation, or production activation. Every branch remains blocked from direct merge until a separate scoped extraction PR passes validation and human review.

