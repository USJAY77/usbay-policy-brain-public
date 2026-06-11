# PB-149 Core Runtime Extraction Program

Decision: VERIFIED

Status: REVIEW_READY

Merge Readiness: FAIL_CLOSED_NOT_MERGE_READY

## Purpose

Define the extraction program for the `runtime_governance_core` backlog identified by PB-148. This is planning and governance evidence only; it does not extract code or mutate branches.

## Input

- Source: `governance/evidence/pb148/runtime_extraction_reduction_matrix.json`
- Core runtime branches: `38`

## Cluster Counts

- `branch_hygiene_and_release_metadata`: 13
- `gateway_and_policy_runtime`: 25

## Classification Counts

- `PARTIALLY_IN_MAIN`: 24
- `RUNTIME_UNIQUE`: 14

## Extraction Sequence

1. `branch_hygiene_and_release_metadata` - EXTRACT - 13 branches
2. `gateway_and_policy_runtime` - EXTRACT - 25 branches

## Top Core Runtime Candidates

1. `usbay/runtime-branch-hygiene-divergence` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 114 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
2. `usbay/allowed-branch-policy-audit` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 100 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
3. `usbay/branch-policy-alignment` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 100 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
4. `usbay/evidence-backlog-sync` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 95 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
5. `usbay/branch-hygiene-decision-correction` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 89 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
6. `usbay/branch-hygiene-terminal-state-correction` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 89 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
7. `usbay/governance-metadata-authority` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 78 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
8. `usbay/cross-system-automation-orchestrator` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 75 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
9. `usbay/delete-branch-decision-trace` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 75 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
10. `usbay/governance-pr-body-integration` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 75 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
11. `usbay/governance-pr-template-completion` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 75 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
12. `usbay/governance-review-label-failure` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 75 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
13. `usbay/refusal-comment-provenance-trace` - branch_hygiene_and_release_metadata - PARTIALLY_IN_MAIN - score 75 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
14. `usbay/intake-gateway-phase-1-governance` - gateway_and_policy_runtime - RUNTIME_UNIQUE - score 96 - EXTRACT_MINIMAL_DELTA
15. `runtime/governance-runtime-hardening` - gateway_and_policy_runtime - RUNTIME_UNIQUE - score 91 - BLOCKED_UNTIL_TEST_CONTEXT_GAP_CLOSED
16. `usbay/architecture-certification-evidence-gaps` - gateway_and_policy_runtime - PARTIALLY_IN_MAIN - score 85 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
17. `runtime-policy-validator` - gateway_and_policy_runtime - RUNTIME_UNIQUE - score 81 - EXTRACT_MINIMAL_DELTA
18. `usbay/euria-live-assessment-workflow` - gateway_and_policy_runtime - PARTIALLY_IN_MAIN - score 78 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY
19. `usbay/intake-production-readiness-phase-2` - gateway_and_policy_runtime - RUNTIME_UNIQUE - score 71 - EXTRACT_MINIMAL_DELTA
20. `runtime/governance-evidence-signature-pipeline` - gateway_and_policy_runtime - PARTIALLY_IN_MAIN - score 70 - DIFF_AGAINST_MAIN_EXTRACT_MISSING_DELTA_ONLY

## Critical Path

1. `branch_hygiene_and_release_metadata`
2. `gateway_and_policy_runtime`

## Deployment Unlock

- Component that unlocks deployment: `gateway_and_policy_runtime`

## Fail Closed

PB-149 authorizes no merge, branch mutation, code extraction, credential creation, external API call, or production activation. Each extraction must occur in a separate scoped governance/* branch with focused tests, audit evidence, full-suite validation before merge readiness, and human review.

