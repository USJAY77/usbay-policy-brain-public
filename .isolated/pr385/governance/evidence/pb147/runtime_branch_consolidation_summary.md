# PB-147 Runtime Branch Matrix

Decision: VERIFIED

Merge Readiness: FAIL_CLOSED_NOT_MERGE_READY

Status: REVIEW_READY

## Input

Source: `governance/evidence/pb146/backlog_consolidation_matrix.json`

Scope: only branches classified `NEEDS_RUNTIME_EXTRACTION` by PB-146.

## Classification Counts

```json
{
  "EXTRACT_RUNTIME": 83,
  "BLOCKED": 1
}
```

## Prioritized Top-10 Execution List

1. `runtime/governance-runtime-hardening` - BLOCKED - score 73 - Known mixed or incomplete validation branch; keep fail-closed until blockers are resolved.
2. `runtime/governance-evidence-signature-pipeline` - EXTRACT_RUNTIME - score 88 - Extract minimal runtime delta into a scoped branch and run focused tests before PR.
3. `usbay/intake-production-readiness-phase-2` - EXTRACT_RUNTIME - score 82 - Extract minimal runtime delta into a scoped branch and run focused tests before PR.
4. `usbay/runtime-branch-hygiene-divergence` - EXTRACT_RUNTIME - score 68 - Extract minimal runtime delta into a scoped branch and run focused tests before PR.
5. `usbay/euria-live-assessment-workflow` - EXTRACT_RUNTIME - score 67 - Extract minimal runtime delta into a scoped branch and run focused tests before PR.
6. `runtime-policy-validator` - EXTRACT_RUNTIME - score 66 - Extract minimal runtime delta into a scoped branch and run focused tests before PR.
7. `usbay/euria-demo-integration` - EXTRACT_RUNTIME - score 62 - Extract minimal runtime delta into a scoped branch and run focused tests before PR.
8. `usbay/intake-gateway-phase-1-governance` - EXTRACT_RUNTIME - score 58 - Extract minimal runtime delta into a scoped branch and run focused tests before PR.
9. `governance/media-production-gap-scaffolding` - EXTRACT_RUNTIME - score 56 - Extract minimal runtime delta into a scoped branch and run focused tests before PR.
10. `governance/rfc3161-timestamp-policy-scaffold` - EXTRACT_RUNTIME - score 54 - Extract minimal runtime delta into a scoped branch and run focused tests before PR.

## Action Rules

SAFE_DELETE: delete only after explicit human confirmation and audit dependency check.

ALREADY_IN_MAIN: verify represented code/evidence in `main`, then decide whether branch can be deleted.

REVIEW_REQUIRED: inspect branch purpose, evidence, tests, and PR lineage before action.

EXTRACT_RUNTIME: create a clean minimal runtime-delta branch and run focused validation before PR.

BLOCKED: keep fail-closed until specific blockers close.

## Fail Closed

No merge, deletion, push, PR creation, runtime mutation, credential creation, production activation, or external call is authorized by PB-147.
