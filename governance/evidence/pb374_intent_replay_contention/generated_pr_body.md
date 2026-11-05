## PURPOSE
Prevent same-process first-use SQLite contenders from opening overlapping connections to the same replay database. This runtime repair is separate from instruction PR425.

## RISK
Previously reproduced native concurrency cases returned zero ALLOW results with SQLITE_BUSY. A repair must preserve durable replay consumption and must never permit two winners.

## POLICY LINK
Baseline AGENTS.md; existing signed intent bindings and fail-closed replay contract; PB-023 and PB-026 generated review metadata. PB-374 is a new administrative repair identifier, not an operational authority grant.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Owner authorized separate Draft PR publication and one native CI cycle for this prepared repair.
- Keep timeout=0, BEGIN IMMEDIATE, synchronous=FULL, schema/version/integrity checks, atomic pair insertion and durable replay checks.
- Preserve exactly-one-winner assertion and 16 reproduction cases; no automatic CI rerun.
- No merge, deployment, activation, permission or trust changes. Replit checkout is outside this batch.

## AUDIT
Reproduction HEAD 942f3fe7257149ea546194273195eae404515a13: run42050425153 attempt1 reported 2831 passed, 2 failed, 194 subtests passed. Cases5 and9 observed zero ALLOW and SQLITE_BUSY/code5. Exact failing SQLite statement remains UNKNOWN. Native evidence: https://github.com/USJAY77/usbay-policy-brain-public/actions/runs/42050425153/job/127324750996 .

## IMPACT
Reject local contenders before SQLite connection creation while leaving SQLite as the independent cross-process transaction fence. This proposes availability repair; it does not grant execution authority or establish production readiness.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL
## MECHANISM
A per-path, reference-counted local nonblocking gate spans connection opening through close. Busy callers fail closed; inactive entries are removed. No SQL retry, schema change or authority change.

## GAP
Repair effectiveness is PARTIAL until native CI. Python3.12.14 AST parsing passed; local pytest invocation failed before collection because pytest is absent. No dependencies installed. Cross-process contention, path aliases and forked-worker availability are not repaired or newly proven. Existing authority gaps remain open.

## VALIDATION
AST parsing, preserved transaction-body comparison and two new targeted regression tests prepared. Preserve the 16 native reproduction cases plus existing identity, tenant, expiry, replay, storage and recovery tests in the governance CI lane.

## ROLLBACK
Any later reversal requires its own authorized source change. Do not rewrite consumed records or prior failure evidence.

## SOURCE
https://github.com/USJAY77/usbay-policy-brain-public/commit/227c5144c63c715a09acf0be41ef8fe8a918a071

## CHANGED FILES
- security/intent_replay_store.py
- tests/test_intent_replay_store_admission.py
- tests/test_intent_governance.py
- governance/evidence/pb374_intent_replay_contention/metadata.json
- governance/evidence/pb374_intent_replay_contention/generated_pr_body.md

## VALIDATION RESULTS
Static preparation only at publication. New-head native CI pending; no local pytest cases collected. Two new test functions cover held-commit connection admission, independence of another database and cleanup after connect failure.

## ROLLBACK PLAN
If native validation fails, keep this Draft PR unmerged and preserve sanitized failure evidence. No automatic retry or deployment.

## COMMIT OR SOURCE REFERENCE
Base 227c5144c63c715a09acf0be41ef8fe8a918a071; reproduction 942f3fe7257149ea546194273195eae404515a13.
