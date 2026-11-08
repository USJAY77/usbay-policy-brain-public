# RISK / MECHANISM / GAP / AUDIT / IMPACT

## STATUS

Dormant synthetic correction only. NOT ADOPTED — NO PRODUCTION AUTHORITY.
New isolated candidate: producer-trust-atomic-time-20261108.
No production root/policy/time source, loader integration or operational recovery.

## Source / candidate identities

Repository: USJAY77/usbay-policy-brain-public
Observed before/after branch: integrate/gitless-runtime-seven-files-771007f1
HEAD: 3fdd34305311f2e4a97d34544c95d87e0dbf781c
Tree: ae0f1774ed72add2da4a62d4f6203dca4cfc39d0
Normal status: empty; tracked and staged differences: empty.
Initial identity was observed by this task's first read-only Git calls;
no exact initial observation timestamp was retained.
Expected unchanged index inventory:
ca2f1cea701600a507d62ef4b5fcfc13c99b8101b26dbcca8887120950fee2a3

Preserved predecessor:
.local/isolated-candidates/producer-trust-corrected-20261108/
MANIFEST SHA256:
9c3fcc25a74f48cb4b0042c2c2d5af3be06448624a6956011ac9779f66310aa8
All 88 predecessor files are unchanged, including all earlier failure logs.
The earlier producer-trust-20261108 and its ten manifest files are also retained:
9ed03468855b5680e7661fbbc5926caa4d3af2b97203b26683f7026a17bf259b

New identity is the newly sealed MANIFEST.json, not a Git branch/commit/tree.
Its inventory binds every local source/document/run file, excluding only itself.

## RISK / findings

R1: supported reentrant callbacks could accept an inner operation at time 110,
return 100, then accept an outer operation expiring at 105, or overwrite newer
currentness with a higher-version but expired-by-known-time snapshot.
Equal-version retries could forget later observed time.

R2: direct release write followed by a failing nonce write could partially commit
accepted state without reserving its replay nonce.

Both findings are reproduced BEFORE correction using deterministic synthetic
signatures and fault injection against exact preserved predecessor source.

## MECHANISM / changes

synthetic_fence.py:
- per exact target/authority known-time high-watermark;
- latest aggregate fetched after each clock callback, all predicates then checked;
- high-watermark updated for eligible authenticated same-version observations;
- immutable aggregate with read-only mapping views;
- release, nonce and time prepared privately before single-reference publication;
- expected-state identity check before publication;
- exception-safe currentness/conflict/time preparation and preallocated rejection;
- copies returned to observers.

contracts.py/verifier.py/test_synthetic.py/test_review.py remain byte-identical.
test_boundary.py adds 21 cases, retaining 64 inherited cases and all 163 subtests.
The R2 regression injects failure at the old nonce write in reproduction and at
the equivalent completed private nonce preparation in the corrected candidate.
Both variants must actually raise the named synthetic MemoryError, preserve
accepted state, and allow a later complete retry with matching nonce reservation.
Assertions have not been replaced with successful verification stubs.

run_bound_suite.py: reuses existing recorder, now verifies predecessor manifest/
88 files, preserves new boundary test source, and selects BoundaryTests.
No application/fixture payload is materialized.

## AUDIT / actual execution

Existing Python 3.11.14, cryptography 50.0.0; no dependency installation.
Command prefix:

    /usr/bin/env -i /home/runner/workspace/.pythonlibs/bin/python3 -I -B \
      .local/isolated-candidates/producer-trust-atomic-time-20261108/run_bound_suite.py

1. reproduce run-01-r1-r2-before-correction:
   4 cases, 0 subtests, 4 assertion failures, 0 errors, exit 1.
   Reproduces both reentrant time orders, exact retry rollback, and partial nonce
   commit. Preserved snapshots use predecessor implementation hashes.
   pre/post inventory: 11e29846d20517a7b1d691bc1a54a99d13cda80273d11cddc38b32df82ca2d72
   stdout: 90624054df51fb97d46b257665101a428e8045394aa56347da8af631451b8331
   stderr: a92dcc3f1c51498c7bcda09f6c8b9be8ddf442e94c83c182e014e8fec63741da
2. final run-02-corrected-complete:
   84 cases, 163 subtests, 0 failures/errors/skips, exit 0.
   pre/post inventory: 47972ee4035c138a91c022762a517cec9f09f24df09f91d5515c7dc40a40709d
3. final run-03-final-boundary:
   85 cases, 163 subtests, 0 failures/errors/skips, exit 0.
   Additional self-review improvement: conflict outcome allocation is performed
   before publication, with its own deterministic allocation-failure regression.
   pre/post inventory: c19987564ab4f1b154a759b447a086eb6732c15e8356e2fe684d8ec02780517b
   stdout: 45b16bdea59a2194315193dde730e28ca13cb38719894c03d93f9b7fb94a873a
   stderr: ec98cf884f0973bf6f76c1eaebf57d6e0f8abc8c30f9b728aaa01b70441a4cf9

Final unique count is 85, not the sum of reruns; subtests are separately counted.
All three runs retain pre/post/runner/result JSON, source snapshots and separate
stdout/stderr. Final seven root source files match final preserved source bytes.
The child runs -I -B with empty environment, close_fds, DEVNULL input, task-only
cwd, 20-second timeout and process-group cleanup. No timeout occurred.
Actual sys.modules delta is recorded with file paths, not a hardcoded success.
No new app-prefix modules were observed; bootstrap/native/kernel claims excluded.
Synthetic private keys are ephemeral, memory-only, never printed or persisted.

## Final self-review

READY_FOR_SCOPED_REVIEW, not independent human approval/security certification.
R1: target/context, time and expiry checks follow final callback and latest-state
capture. Equal-version observations remember time; retries check currentness and
expiry before idempotence. Wrong-scope/unauthenticated/expired/foreign-context/
rollback observations cannot raise known time. Other exact tenant contexts are
separate. Tests assert inner valid results survive rejected outer operations.
R2: all fallible dictionary/aggregate/outcome preparation precedes one publication;
release/nonces cannot publish separately. Fault tests cover release/nonce/time
preparation, snapshot/release publication boundary, conflict preparation and
outcome allocation. Intentional authenticated ambiguity is a consistent knowledge
transition and never an accepted-release advance.
Earlier F1/F2/F4: authentication, frozen bindings, strict parsing, role checks,
signature/threshold checks unchanged; all inherited assertions rerun.
F3: fresh source-bound execution evidence only; no retroactive historical proof.

## GAP

Process-local synthetic fence only. No crash durability, persistent rollback
protection, distributed transaction, trusted production time/custody/registry,
root adoption, actual artifact/dependency/image byte verification or serving
attestation. Arbitrary privileged same-process mutation/patching, interpreter
bootstrap and asynchronous interruption are not independently attested.
Local ignored files and hashes do not prove durable external preservation.

## IMPACT / prohibited operations

No tracked app, loader/startup, manifest contract, config/secrets, active service,
real trust or production state changed. No real signing/key handling, install,
app import, provider/network call, service startup/restart, commit/push/PR/merge,
build, publish/deploy/promote or activation. No workflow or permission change.
Visible failed Promote/crashloop is outside scope: cause/initiator UNKNOWN.
No Fix with Agent, republish or deployment diagnostic was invoked.
