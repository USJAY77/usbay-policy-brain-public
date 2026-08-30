# USBAY Execution Scheduler

## Purpose

The Execution Scheduler builds deterministic scheduling metadata for governed
development tasks. It models dependency order, retry metadata, timeout metadata,
queue metadata, and priority metadata.

It is a scheduler contract only. It validates local metadata and returns
hash-only decisions. It never starts, queues, dispatches, polls, retries, or
executes work.

## Safety Boundaries

- No threads.
- No async execution.
- No subprocess.
- No process spawning.
- No sockets.
- No network.
- No runtime execution.
- No provider, API, or LLM calls.
- No production activation.

## Contract

Allowed scheduler states are fixed to:

- READY
- WAITING
- BLOCKED
- FAILED
- FINISHED

Allowed task capabilities are fixed local metadata labels:

- agent_runtime
- audit
- event_bus
- governance_validation
- metadata
- runtime_coordinator
- runtime_health

Allowed queue labels are:

- audit
- default
- governance
- runtime

Task metadata may contain only hash/reference fields:

- audit_hash
- human_approval_hash
- metadata_hash

## Fail-Closed Rules

The scheduler blocks missing governance metadata, unknown tasks, duplicate task
IDs, unknown dependencies, dependency cycles, invalid retry metadata, invalid
timeout metadata, invalid priority metadata, invalid queue metadata, unknown
capabilities, unknown metadata fields, raw payload metadata, unknown scheduler
states, and any execution request.

## Evidence

All scheduler outputs are hash-only, redacted, deterministic, and local. Evidence
contains only hashes, fixed booleans, schema/version metadata, denial reasons,
and remaining gaps. It must not contain credentials, raw payloads, provider data,
network data, subprocess output, or production configuration.

## Remaining Gaps

- No live worker queue is implemented.
- Scheduling metadata is not connected to production execution.
