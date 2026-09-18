# Focused containment validation patch review

The original seven-case harness is not scheduled here. Shared cleanup and
scheduler helpers are hardened by this increment, so the seven-case
implementation is not claimed unchanged.
This patch adds a separate focused entrypoint, `run_containment.py`, for A1,
A2, and B only. No containment or lifecycle case is executed by this patch.

## Future batch

Only these seven cases are scheduled:

1. `term-to-kill`
2. `cleanup-denial`
3. `probe-exception`
4. `drain-exception`
5. `cleanup-signal-SIGINT`
6. `cleanup-signal-SIGTERM`
7. `cleanup-signal-SIGHUP`

Future output is isolated under
`validation/fda_launcher/evidence/missing_cases_batch/`; the existing evidence
directory is neither overwritten nor used for reruns. The eight previously
completed results remain preserved and are not scheduled again.

## Extraction and instrumentation

`run_validation.py` verifies the pinned launcher and programmatically extracts
the constants/imports/functions preceding `main()` from its embedded Python.
The extracted supervisor functions are not edited. Test-only instrumentation is
external: a namespace-local `subprocess.Popen` wrapper records ownership and,
for `term-to-kill`, waits for a readiness file; named namespace globals are
monkeypatched only for the denial, probe, drain, and cleanup-signal cases.
The original `signal_group` is called unchanged for `term-to-kill`; TERM is
never faked.

## Containment and timing

Before worker spawn, the parent reserves nonce-specific ownership, result, and
worker-authorization paths. It records and independently validates the worker
PID=PGID=session leader, case, and nonce, then releases only that nonce-bound
authorization channel. The worker cannot extract or spawn the supervisor child
before that channel is released.

Every focused synthetic child starts behind a controller-owned one-way release
pipe and
appends only complete JSONL observations. The controller retains live
`OwnedHandle` objects, including pidfds opened at creation. The worker transfers
the child pidfd over a case-scoped inherited Unix socket using `SCM_RIGHTS`
before any crash injection. Focused signals use `signal.pidfd_send_signal`;
JSONL is evidence, never signal authority. PGID/session probes are observation
only. Residual groups are containment-unknown and no unregistered descendant is
targeted.

Each case has a fresh 12 second execution budget. This is conservative for the
`0.08` second supervisor wait plus exact extracted 2 second TERM grace, exact
2 second KILL grace, possible direct-child fallback TERM/KILL waits, and
startup/readiness margin. Only after that execution wait ends does a distinct
3 second watchdog-cleanup deadline begin for worker reap and child-group
absence verification. There is no shared operational deadline and no claim
that the whole seven-case batch is hard-bounded. Hard bounding of final
evidence file writes is a documented limitation.

Parent-side worker identity, ownership-record, or authorization-channel failures
kill and reap the exact still-gated worker before returning a failed no-child
result. Worker dispatch uses the complete case, ownership, result,
authorization, and nonce argument set.

For each cleanup-signal case, the wrapper checkpoint records `phase=term` and
the exact requested signal, the helper records a post-`os.kill` sent event, and
assertions require exact signal identity, `cleanup-pending-drain`, and strict
checkpoint < sent < signal-delivery ordering, in addition to status/reason.
The denial case separately requires exact TERM-denied and KILL-denied trace
tuples.

Containment requires exactly one nonce-, case-, and worker-bound supervisor
child record in addition to the worker record. The watchdog evaluates ownership
before reading the worker result, uses the same helper as the seven-case
harness, and in focused mode signals only transferred live pidfds. Direct-child
`Popen` handles distinguish termination observation from reaping.

Every synthetic is a direct Python process. Before release-pipe waiting or test
behavior it configures Linux `prctl(PR_SET_PDEATHSIG, SIGKILL)` through
`ctypes`, then compares `os.getppid()` to the expected worker PID. This closes
the fork/prctl race: a worker death before `prctl` is caught by the PPID check,
and a death after `prctl` causes kernel SIGKILL. The configured mechanism is
recorded as test evidence but not claimed as runtime proof. This is Linux-only,
test-owned child-lifetime instrumentation, not universal production
containment. The parent never claims to discover an unpersisted child; it can
only clean validated persisted PGIDs. SIGKILL also cannot universally
guarantee timely disappearance for kernel-uninterruptible processes.

Case scheduling is explicit and fail-closed. After retaining each complete
result, the scheduler separately requires proven ownership containment, worker
reaping, no remaining owned groups, well-formed ownership/cleanup evidence, and
no containment-related assertion failure. An expected injected supervisor
failure does not stop scheduling when those independent harness-cleanup checks
remain proven. Any containment contradiction or unexpected case exception
stops further execution and records every remaining case as `NOT_EXECUTED` with
the blocking case and reason.

## Planning boundary

The existing eight results and evidence are preserved and are not scheduled for
rerun. The existing assessment's Mac next-step text is superseded for planning
purposes only, without changing any evidence: the next Mac step is **UNDECIDED**.
The AST syntax parse is preparation only and is not a validation case.
Executable self-tests are isolated synthetic checks with injected fakes, not
static analysis. No `diskutil`/Full Disk Access diagnostic is authorized by
this patch.

## Focused containment entrypoint

`run_containment.py` chooses and creates a fresh
`evidence/containment_<timestamp>_<nonce>/` directory with `exist_ok=False`.
It validates worker and child PID=PGID=session identities and nonce/case before
any crash or cleanup signal. A1 deliberately releases the child before
`prctl`; worker death then permits the child to observe the PPID mismatch. A2
requires the post-`prctl`/PPID checkpoint and remains held until worker death.
This focused A1 ordering differs from the seven-case synthetic guard, whose
child configures `prctl` before its PPID check;
both keep the ordinary ownership record empty. B proves guard readiness before
the exact 12-second execution interval, then records timeout, fresh cleanup
start/deadline/completion and elapsed cleanup against the 3-second budget.
Errors retain structured exception and handle-cleanup evidence and stop
scheduling. No signal is inferred where observation cannot establish it.

Focused authority is limited to transferred pidfds for known direct process
leaders. Synthetic groups are assumed singleton for this test; PGID probes only
observe residual groups and do not provide atomic group containment. The direct
worker `Popen` is reaped by its controller. Controller-owned one-way release
pipes are inherited by children; children never write the release primitive.
SCM_RIGHTS descriptors are rejected unless the message, ancillary count/type/
length, and `/proc/self/fdinfo` `Pid:` binding all match the expected child.
Malformed and unterminated JSONL is retained as separate evidence and cannot
advance a checkpoint.
The focused cleanup context records the original exception, observations,
pidfd attempts, separate termination observation, direct reaping, residual
groups, errors, and monotonic cleanup timing. Cleanup is PROVEN only when all
registered singleton leader groups are absent and the direct worker is reaped;
otherwise scheduling stops as UNKNOWN. Persisted ownership JSONL is returned
as `ordinary_ownership_records`; derived annotations are separate and never
written back into the raw persisted record.

Each future run records pre- and post-execution SHA-256 values for both
harness sources. `PROVEN` source stability means only that those values are
equal; pre/post hashes cannot prove absence of transient changes during
execution. Historical execution-to-source binding remains UNKNOWN.

Later execution command (only these three cases):

`python3 validation/fda_launcher/run_containment.py`

Static-only check for this patch:

`python3 -c "import ast, pathlib; [ast.parse(pathlib.Path(p).read_text()) for p in ('validation/fda_launcher/run_validation.py', 'validation/fda_launcher/run_containment.py')]"`

The two executable self-test routes are separate isolated synthetic checks,
not static checks:

`python3 validation/fda_launcher/run_containment.py --state-machine-self-test`

`python3 validation/fda_launcher/run_containment.py --fault-checks`

They must use injected fakes and must not create a child, execute a
containment case, signal a real process, or open runtime channels. The AST
command is static analysis only; executable synthetic checks exercise the
checkpoint parser, exact identity predicates, fail-closed scheduler, cleanup
blockers, CLI side-effect isolation, and source-stability mismatch.

## Original artifact hashes

- Launcher:
  `b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b`
- Proposal:
  `ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c`# Focused containment validation patch review

The original seven-case harness is not scheduled here. Shared cleanup and
scheduler helpers are hardened by this increment, so the seven-case
implementation is not claimed unchanged.
This patch adds a separate focused entrypoint, `run_containment.py`, for A1,
A2, and B only. No containment or lifecycle case is executed by this patch.

## Future batch

Only these seven cases are scheduled:

1. `term-to-kill`
2. `cleanup-denial`
3. `probe-exception`
4. `drain-exception`
5. `cleanup-signal-SIGINT`
6. `cleanup-signal-SIGTERM`
7. `cleanup-signal-SIGHUP`

Future output is isolated under
`validation/fda_launcher/evidence/missing_cases_batch/`; the existing evidence
directory is neither overwritten nor used for reruns. The eight previously
completed results remain preserved and are not scheduled again.

## Extraction and instrumentation

`run_validation.py` verifies the pinned launcher and programmatically extracts
the constants/imports/functions preceding `main()` from its embedded Python.
The extracted supervisor functions are not edited. Test-only instrumentation is
external: a namespace-local `subprocess.Popen` wrapper records ownership and,
for `term-to-kill`, waits for a readiness file; named namespace globals are
monkeypatched only for the denial, probe, drain, and cleanup-signal cases.
The original `signal_group` is called unchanged for `term-to-kill`; TERM is
never faked.

## Containment and timing

Before worker spawn, the parent reserves nonce-specific ownership, result, and
worker-authorization paths. It records and independently validates the worker
PID=PGID=session leader, case, and nonce, then releases only that nonce-bound
authorization channel. The worker cannot extract or spawn the supervisor child
before that channel is released.

Every focused synthetic child starts behind a controller-owned one-way release
pipe and
appends only complete JSONL observations. The controller retains live
`OwnedHandle` objects, including pidfds opened at creation. The worker transfers
the child pidfd over a case-scoped inherited Unix socket using `SCM_RIGHTS`
before any crash injection. Focused signals use `signal.pidfd_send_signal`;
JSONL is evidence, never signal authority. PGID/session probes are observation
only. Residual groups are containment-unknown and no unregistered descendant is
targeted.

Each case has a fresh 12 second execution budget. This is conservative for the
`0.08` second supervisor wait plus exact extracted 2 second TERM grace, exact
2 second KILL grace, possible direct-child fallback TERM/KILL waits, and
startup/readiness margin. Only after that execution wait ends does a distinct
3 second watchdog-cleanup deadline begin for worker reap and child-group
absence verification. There is no shared operational deadline and no claim
that the whole seven-case batch is hard-bounded. Hard bounding of final
evidence file writes is a documented limitation.

Parent-side worker identity, ownership-record, or authorization-channel failures
kill and reap the exact still-gated worker before returning a failed no-child
result. Worker dispatch uses the complete case, ownership, result,
authorization, and nonce argument set.

For each cleanup-signal case, the wrapper checkpoint records `phase=term` and
the exact requested signal, the helper records a post-`os.kill` sent event, and
assertions require exact signal identity, `cleanup-pending-drain`, and strict
checkpoint < sent < signal-delivery ordering, in addition to status/reason.
The denial case separately requires exact TERM-denied and KILL-denied trace
tuples.

Containment requires exactly one nonce-, case-, and worker-bound supervisor
child record in addition to the worker record. The watchdog evaluates ownership
before reading the worker result, uses the same helper as the seven-case
harness, and in focused mode signals only transferred live pidfds. Direct-child
`Popen` handles distinguish termination observation from reaping.

Every synthetic is a direct Python process. Before release-pipe waiting or test
behavior it configures Linux `prctl(PR_SET_PDEATHSIG, SIGKILL)` through
`ctypes`, then compares `os.getppid()` to the expected worker PID. This closes
the fork/prctl race: a worker death before `prctl` is caught by the PPID check,
and a death after `prctl` causes kernel SIGKILL. The configured mechanism is
recorded as test evidence but not claimed as runtime proof. This is Linux-only,
test-owned child-lifetime instrumentation, not universal production
containment. The parent never claims to discover an unpersisted child; it can
only clean validated persisted PGIDs. SIGKILL also cannot universally
guarantee timely disappearance for kernel-uninterruptible processes.

Case scheduling is explicit and fail-closed. After retaining each complete
result, the scheduler separately requires proven ownership containment, worker
reaping, no remaining owned groups, well-formed ownership/cleanup evidence, and
no containment-related assertion failure. An expected injected supervisor
failure does not stop scheduling when those independent harness-cleanup checks
remain proven. Any containment contradiction or unexpected case exception
stops further execution and records every remaining case as `NOT_EXECUTED` with
the blocking case and reason.

## Planning boundary

The existing eight results and evidence are preserved and are not scheduled for
rerun. The existing assessment's Mac next-step text is superseded for planning
purposes only, without changing any evidence: the next Mac step is **UNDECIDED**.
The AST syntax parse is preparation only and is not a validation case.
Executable self-tests are isolated synthetic checks with injected fakes, not
static analysis. No `diskutil`/Full Disk Access diagnostic is authorized by
this patch.

## Focused containment entrypoint

`run_containment.py` chooses and creates a fresh
`evidence/containment_<timestamp>_<nonce>/` directory with `exist_ok=False`.
It validates worker and child PID=PGID=session identities and nonce/case before
any crash or cleanup signal. A1 deliberately releases the child before
`prctl`; worker death then permits the child to observe the PPID mismatch. A2
requires the post-`prctl`/PPID checkpoint and remains held until worker death.
This focused A1 ordering differs from the seven-case synthetic guard, whose
child configures `prctl` before its PPID check;
both keep the ordinary ownership record empty. B proves guard readiness before
the exact 12-second execution interval, then records timeout, fresh cleanup
start/deadline/completion and elapsed cleanup against the 3-second budget.
Errors retain structured exception and handle-cleanup evidence and stop
scheduling. No signal is inferred where observation cannot establish it.

Focused authority is limited to transferred pidfds for known direct process
leaders. Synthetic groups are assumed singleton for this test; PGID probes only
observe residual groups and do not provide atomic group containment. The direct
worker `Popen` is reaped by its controller. Controller-owned one-way release
pipes are inherited by children; children never write the release primitive.
SCM_RIGHTS descriptors are rejected unless the message, ancillary count/type/
length, and `/proc/self/fdinfo` `Pid:` binding all match the expected child.
Malformed and unterminated JSONL is retained as separate evidence and cannot
advance a checkpoint.
The focused cleanup context records the original exception, observations,
pidfd attempts, separate termination observation, direct reaping, residual
groups, errors, and monotonic cleanup timing. Cleanup is PROVEN only when all
registered singleton leader groups are absent and the direct worker is reaped;
otherwise scheduling stops as UNKNOWN. Persisted ownership JSONL is returned
as `ordinary_ownership_records`; derived annotations are separate and never
written back into the raw persisted record.
The scheduler also requires typed, finite cleanup start/deadline/completion
timestamps, a nonnegative elapsed duration consistent with those timestamps,
the configured cleanup budget, and `cleanup_deadline_started=true`.

Each future run records pre- and post-execution SHA-256 values for both
harness sources. `PROVEN` source stability means only that those values are
equal; pre/post hashes cannot prove absence of transient changes during
execution. Historical execution-to-source binding remains UNKNOWN.

Later execution command (only these three cases):

`python3 validation/fda_launcher/run_containment.py`

Static-only check for this patch:

`python3 -c "import ast, pathlib; [ast.parse(pathlib.Path(p).read_text()) for p in ('validation/fda_launcher/run_validation.py', 'validation/fda_launcher/run_containment.py')]"`

The two executable self-test routes are separate isolated synthetic checks,
not static checks:

`python3 validation/fda_launcher/run_containment.py --state-machine-self-test`

`python3 validation/fda_launcher/run_containment.py --fault-checks`

They must use injected fakes and must not create a child, execute a
containment case, signal a real process, or open runtime channels. The AST
command is static analysis only; executable synthetic checks exercise the
checkpoint parser, exact identity predicates, fail-closed scheduler, cleanup
blockers, CLI side-effect isolation, and source-stability mismatch.

## Original artifact hashes

- Launcher:
  `b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b`
- Proposal:
  `ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c`