## PURPOSE
Prevent same-process first-use SQLite contenders from opening overlapping connections to the same replay database. This runtime repair is separate from instruction PR425. Correct P1 review finding 4482761885: discard inherited process-local admission locks in POSIX children without changing SQLite state.

## RISK
Previously reproduced native concurrency cases returned zero ALLOW results with SQLITE_BUSY. A repair must preserve durable replay consumption and must never permit two winners. The original gate can inherit a locked database gate or registry mutex into a forked child and deny indefinitely or hang.

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
- Owner authorized this fork correction, four regression cases, one new CI cycle and targeted re-review. Do not automatically retry CI or resolve the review thread.

## AUDIT
Reproduction HEAD 942f3fe7257149ea546194273195eae404515a13: run42050425153 attempt1 reported 2831 passed, 2 failed, 194 subtests passed. Cases5 and9 observed zero ALLOW and SQLITE_BUSY/code5. Exact failing SQLite statement remains UNKNOWN. Native evidence: https://github.com/USJAY77/usbay-policy-brain-public/actions/runs/42050425153/job/127324750996 . Initial repair 7d3667fa0a4271128c25f43f5f0b9c67f502e5d3 passed native run42058759805 attempt1: 2835 tests and 194 subtests. Codex code review then reported P1 finding4482761885. Preserve that finding and initial successful CI as scoped historical evidence, not proof of fork correctness.

## IMPACT
Reject local contenders before SQLite connection creation while leaving SQLite as the independent cross-process transaction fence. This proposes availability repair; it does not grant execution authority or establish production readiness. Child-local reset changes neither durable consumed rows nor parent-process locks; SQLite remains the cross-process fence.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL
## MECHANISM
A per-path, reference-counted local nonblocking gate spans connection opening through close. Busy callers fail closed; inactive entries are removed. No SQL retry, schema change or authority change. Register after_in_child through os.register_at_fork where available. Replace the child registry lock and dictionary without acquiring inherited Python locks. No SQLite connection, consumed record, signature, authority or policy is reset.

## GAP
New-head native CI and independent review are pending. Local auxiliary execution used the four prepared test bodies under Python3.12.14, not pytest; pytest is absent locally. Path aliases, general cross-process contention and reuse of inherited in-flight SQLite connections are outside the demonstrated repair. Existing product authority gaps remain open.

## VALIDATION
Four POSIX-fork cases combine inherited database/registry locks with and without a separate held SQLite exclusive transaction. Each child has a bounded five-second pipe deadline and cleanup. Check parent lock retention and exact durable row count. Preserve existing 16 exactly-one-winner cases and all governance regressions. One new native CI cycle only.

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
- tests/test_intent_replay_store_fork.py

## VALIDATION RESULTS
Auxiliary standard-library execution of the four regression bodies reproduced three baseline failures (one baseline fence case already passes); the corrected candidate passed all four. Python3.12.14. A multithreaded-fork DeprecationWarning was observed and preserved. This is not a pytest or authoritative-runtime result. New-head native pytest CI pending.

## ROLLBACK PLAN
If native validation fails, keep this Draft PR unmerged and preserve sanitized failure evidence. No automatic retry or deployment.

## COMMIT OR SOURCE REFERENCE
Base 227c5144c63c715a09acf0be41ef8fe8a918a071; repair parent 7d3667fa0a4271128c25f43f5f0b9c67f502e5d3; finding https://github.com/USJAY77/usbay-policy-brain-public/pull/426#discussion_r4482761885 .
