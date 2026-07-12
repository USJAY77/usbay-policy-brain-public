# USBAY Execution Scheduler

## Purpose

The Execution Scheduler builds deterministic scheduling metadata for governed
development tasks. It models dependency order, retry metadata, timeout metadata,
queue metadata, and priority metadata.

## Safety Boundaries

- No threads.
- No async execution.
- No subprocess.
- No process spawning.
- No runtime execution.
- No provider, API, or LLM calls.

## Fail-Closed Rules

The scheduler blocks missing governance metadata, unknown tasks, duplicate task
IDs, unknown dependencies, dependency cycles, invalid retry metadata, invalid
timeout metadata, raw payload metadata, and any execution request.

## Evidence

All scheduler outputs are hash-only, redacted, deterministic, and local.

## Remaining Gaps

- No live worker queue is implemented.
- Scheduling metadata is not connected to production execution.
