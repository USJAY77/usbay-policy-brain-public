# Bounded native Linux validation plan

Preparation only. None of the commands below were executed in this task.

## Source identity preconditions

Every future native attempt must first require:

```text
run_containment.py  97b73cb45f341a590e97ae375f24e35e32173e06ff0e74165420b6e7ce0da55d
run_validation.py   eb71d8437867dd90749870c28794a976a3798264e301da2072b12d1e9f699266
```

If either identity changes, this plan and all historical results become stale.
Record branch, HEAD, status, interpreter version, source pre-hashes, exact
command, stdout, stderr, exit state, timeout state, source post-hashes, and all
created evidence for each separately authorized attempt.

## Outer-controller rule

Do not treat a generic `timeout` wrapper as sufficient containment. The
controller creates workers and children in separate sessions/process groups.
Killing only the controller can prevent its `finally`/error path from calling
`cleanup_active_case`, leaving separately grouped descendants alive.

A future runner must retain live authority outside the controller for every
created process group, or run the entire attempt inside an independently
managed cgroup/systemd scope whose kill and empty-state semantics are directly
verified. The outer runner must:

1. establish the containment boundary before starting the controller;
2. record the controller identity and boundary identity;
3. allow the controller's internal execution deadline to expire first;
4. allow a distinct cleanup interval after controller completion or failure;
5. on controller timeout, signal the whole verified boundary, not a guessed PID;
6. wait until the boundary is empty and reap every direct child it owns;
7. report `UNKNOWN` or `FAILED`, never success, if boundary-empty proof is absent;
8. preserve evidence even if the controller exits nonzero or is killed.

No existing repository command establishes that outer boundary. Native
commands below are therefore reviewable entrypoints, not authorization to run.

## Focused A1, A2, and B

### Existing entrypoints

```bash
python3.11 validation/fda_launcher/run_containment.py
python3.11 validation/fda_launcher/run_containment.py --cases A2 B
```

The no-argument form executes A1, A2, then B. The second executes only A2 and
B; there is no existing CLI selector for A1 alone, A2 alone, or B alone.

### Effects and expectations

- Each case creates a worker in a new session/process group.
- Each worker creates a child in another new session/process group.
- Live pidfds plus PID/PGID/session/nonce/case checks authorize signals.
- A1 kills and reaps the worker, then writes the release byte. The child
  continues after that release, observes the PPID mismatch before completing
  guard installation, records the mismatch checkpoint, and exits.
- A2 expects verified `PR_SET_PDEATHSIG(SIGKILL)` plus PPID, followed by child
  termination when the worker is killed.
- B expects watchdog cleanup of separately grouped worker and child, worker
  reaping, child/worker group absence, and cleanup completion within 3 seconds.
- Per-handshake waits are 5 seconds. B uses the shared 3-second cleanup budget.
- In focused containment, the first caught case error causes bounded
  active-case cleanup; later focused cases are marked `NOT_EXECUTED`.

### Evidence and collisions

The controller creates:

```text
validation/fda_launcher/evidence/containment_<UTC-second>_<UUID>/
```

with `exist_ok=False`. UUID naming makes ordinary collision unlikely and
preserves historical directories. `raw.json` is written after the case loop.
If the controller is killed before that write, case observation/ownership
files may remain but the summary and source post-hashes will be absent.

### Current disposition

```text
Entrypoints: SAFE_EXISTING only inside a separately proven outer containment runner
Direct/manual invocation: BLOCKED
```

The missing mechanism is an independently verified outer boundary that can
clean every separate process group if the Python controller is killed.

## Pre-guard fault handling

### Existing entrypoint

```bash
python3.11 validation/fda_launcher/run_containment.py --fault-pre-guard
```

This selects A1, records exact worker and child live handles, and raises a
deterministic controller fault after the child ownership checkpoint but before
the ordinary parent-death guard path. The main error path must call
`cleanup_active_case`, signal only live pidfd-authorized worker/child targets,
reap the worker, prove both groups absent, write the error result, and stop.

Internal timing consists of the 5-second checkpoint/FD-transfer bounds and a
separate 3-second cleanup deadline. The expected controller outcome is a
handled fault attempt with `cleanup_state == "PROVEN"`; absence of that proof
is failure, not a successful fault injection.

Disposition: `BLOCKED` for direct execution pending the same outer containment
runner described above.

## Post-guard fault handling

### Existing entrypoint

```bash
python3.11 validation/fda_launcher/run_containment.py --fault-post-guard
```

This selects A2, releases the child, requires the post-`prctl` PPID checkpoint,
then raises the deterministic controller fault. Cleanup authority and expected
evidence are the same as pre-guard: pidfd-authorized worker/child SIGKILL,
worker reaping, group-absence proof, bounded cleanup, error evidence, and
fail-closed termination.

Internal timing consists of the 5-second pre/post-guard checkpoint bounds and a
separate 3-second cleanup deadline.

Disposition: `BLOCKED` for direct execution pending a proven outer containment
runner.

## Seven-case lifecycle integration

### Existing entrypoint

```bash
python3.11 validation/fda_launcher/run_validation.py
```

It schedules, in order:

```text
term-to-kill
cleanup-denial
probe-exception
drain-exception
cleanup-signal-SIGINT
cleanup-signal-SIGTERM
cleanup-signal-SIGHUP
```

Each case starts a worker in a new session. The worker starts a synthetic
supervisor child in another new session. Each case has a 12-second controller
wait and a 3-second parent-watchdog cleanup budget. Scheduling stops after the
first result for which `containment_blocker()` finds missing, malformed, or
contradictory containment/cleanup proof; later cases are marked
`NOT_EXECUTED`. Non-containment assertion failures such as a status/reason
mismatch are retained in the result but do not independently stop scheduling.

Expected statuses/reasons are source-defined:

```text
term-to-kill             124 timeout-clean
cleanup-denial           125 timeout-cleanup-unproven
probe-exception           70 post-wait-probe-exception-clean
drain-exception          125 pending-signal-drain-cleanup-unproven
cleanup-signal-SIGINT    130 interrupted-clean
cleanup-signal-SIGTERM   143 interrupted-clean
cleanup-signal-SIGHUP    129 interrupted-clean
```

Ownership requires nonce/case/PID/PGID/session equality and exactly one valid
supervisor-child record. Cleanup evidence requires worker reaping, worker and
child group absence, no malformed records or cleanup errors, and completion
within the cleanup deadline.

### Hard-coded evidence collision

The lifecycle command uses the fixed directory:

```text
validation/fda_launcher/evidence/missing_cases_batch
```

and creates it with `exist_ok=False`. That historical directory already exists.
It must not be deleted, renamed, emptied, or reused. Therefore the existing
lifecycle entrypoint cannot currently create collision-free evidence.

Disposition:

```text
Existing command: BLOCKED
Missing mechanism: caller-selectable or collision-resistant evidence directory
                     plus independently verified outer containment
Future harness change required: YES
```

A future bounded change should add an explicit evidence-root argument or
collision-resistant attempt directory while preserving `exist_ok=False`,
historical bytes, source identity records, scheduling-stop behavior, and all
ownership/cleanup assertions. That source change would require its own review
and would invalidate the executable hashes in this plan.

## Controller exit or kill observability

- Normal/handled error exit: focused containment writes `raw.json`; lifecycle
  writes its summary only if it reaches the final evidence-write section.
- Abrupt controller kill: existing per-case observation and ownership files
  may survive, but final source post-hashes, cleanup summary, scheduler stop
  annotations, and boundary-empty proof may be missing.
- `PR_SET_PDEATHSIG` covers a child relative to its immediate worker after the
  guard is installed; it does not prove cleanup for every pre-guard window and
  does not replace outer controller containment.
- Missing final evidence or residual-group proof must classify the attempt as
  `UNKNOWN` or `FAILED`; it must never be promoted to `PROVEN`.

## Authorization boundary

This plan does not authorize any command above. Before a future native run,
human approval must name the exact entrypoint, source hashes, outer containment
mechanism, deadlines, cleanup allowance, and evidence destination.