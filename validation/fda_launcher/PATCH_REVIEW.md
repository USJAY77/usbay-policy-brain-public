# Minimal validation-only patch review

Preparation only. No validation batch was executed by this patch. The harness
and synthetic children were not run. One non-executing AST syntax parse of the
prepared harness is permitted and recorded separately.

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
authorization gate. The worker cannot extract or spawn the supervisor child
before that gate is released.

Every synthetic child starts behind its own nonce-bound child gate and compares
the exact gate contents with its expected nonce before performing test behavior. The
namespace-local `Popen` wrapper records PID, PGID, session ID,
`start_new_session`, worker PID, case, and nonce immediately after spawn,
validates and persists the record, and only then releases the child gate. A
record, validation, gate-release, or readiness failure kills and reaps that
exact child PGID/Popen before raising. Signals are sent only to validated,
nonce-matching, session-leading recorded PGIDs. Malformed or missing records
remain containment-unproven; ambient process groups are never targeted.

Each case has a fresh 12 second execution budget. This is conservative for the
`0.08` second supervisor wait plus exact extracted 2 second TERM grace, exact
2 second KILL grace, possible direct-child fallback TERM/KILL waits, and
startup/readiness margin. Only after that execution wait ends does a distinct
3 second watchdog-cleanup deadline begin for worker reap and child-group
absence verification. There is no shared operational deadline and no claim
that the whole seven-case batch is hard-bounded. Hard bounding of final
evidence file writes is a documented limitation.

Parent-side worker identity, ownership-record, or authorization-gate failures
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
before reading the worker result, kills a validated supervisor-child PGID
separately from the worker PGID when required, and verifies that the recorded
supervisor-child group is absent afterward.

Every synthetic is a direct Python process. Before nonce-gate waiting or test
behavior it configures Linux `prctl(PR_SET_PDEATHSIG, SIGKILL)` through
`ctypes`, then compares `os.getppid()` to the expected worker PID. This closes
the fork/prctl race: a worker death before `prctl` is caught by the PPID check,
and a death after `prctl` causes kernel SIGKILL. The configured mechanism is
recorded as test evidence but not claimed as runtime proof. This is Linux-only,
test-owned child-lifetime instrumentation, not universal production
containment. The parent never claims to discover an unpersisted child; it can
only clean validated persisted PGIDs. SIGKILL also cannot universally
guarantee timely disappearance for kernel-uninterruptible processes.

## Planning boundary

The existing eight results and evidence are preserved and are not scheduled for
rerun. The existing assessment's Mac next-step text is superseded for planning
purposes only, without changing any evidence: the next Mac step is **UNDECIDED**.
The AST syntax parse is preparation only and is not a validation case. No
`diskutil`/Full Disk Access diagnostic is authorized by this patch.

## Original artifact hashes

- Launcher:
  `b19bd48a797b3f5659c6fb850d4baff1792c6c73153bfec13b4eb6f5976f320b`
- Proposal:
  `ef648fadc31e252ce91ff6ee754b0670e6f477b5afd8a5e4a5bc3cdcb675429c`