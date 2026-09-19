# Native execution prerequisites after collision-safe evidence change

## Implemented in this increment

- The seven-case lifecycle no longer targets the fixed active
  `evidence/missing_cases_batch` directory.
- A dispatched lifecycle attempt exclusively creates
  `evidence/missing_cases_<UTC timestamp>_<UUID>`.
- The selected directory is passed explicitly to case execution.
- Case files, extracted source, and `raw.json` remain inside that attempt.
- `raw.json` and every case result record the actual selected destination.
- Complete CLI parsing occurs before dispatch, so help, import, scheduler
  self-test, and malformed input do not allocate lifecycle attempt directories.
- Existing historical evidence is neither reused nor modified.

These statements are supported by static checks and isolated doubles. No
native lifecycle case was executed.

## Outer containment result

`BLOCKED`: no established supported independent backend was available.

Read-only inspection observed cgroup v2 and a `cgroup.kill` file in the
transient shell scope. It did not establish delegated child-cgroup creation,
manager independence, escape prevention, whole-boundary kill behavior,
empty-state behavior, or direct-child reaping. `systemctl` and `systemd-run`
were absent, so no supported systemd user-service mechanism could be reused.

No cgroup/unit was created, no cgroup control was written, no permission was
changed, and no probe workload was started.

## Minimum external environment requirement

A future native run requires a trusted manager outside the controller boundary
that can:

1. create an exact task-owned boundary before releasing the controller;
2. prevent or detect movement of tasks outside that boundary;
3. retain cleanup authority after controller failure or termination;
4. enforce distinct execution and cleanup deadlines;
5. terminate the exact owned boundary without signaling ambient processes;
6. prove boundary emptiness, such as authoritative `cgroup.events populated=0`;
7. reap the direct controller child;
8. persist command, identity, timeout, cleanup, and failure evidence outside
   the boundary;
9. fail closed on setup error, identity mismatch, cleanup error, missing
   empty-state proof, reaping failure, manager failure, or deadline exhaustion.

The manager's own failure must leave the attempt `UNKNOWN` or `FAILED`; it
cannot produce `PROVEN`.

## Remaining authorization boundary

Native A1/A2/B, pre/post-guard faults, and the seven-case lifecycle remain
unauthorized and unexecuted. A separately authorized future task must identify
the concrete external manager, exact source hashes, execution deadline,
cleanup allowance, evidence destination, and stop behavior.

Process containment limits process lifetime and cleanup authority. It is not a
complete security sandbox.