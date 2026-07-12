# USBAY Agent Runtime Coordinator

## Purpose

The Agent Runtime Coordinator models local development-agent coordination for
Codex, Replit, and local terminal actors. It is metadata only and does not
execute actions, start subprocesses, call providers, or activate production.

## State Machine

Supported states:

- `READY`
- `RUNNING`
- `WAITING`
- `BLOCKED`
- `FAILED`
- `FINISHED`

Unknown states fail closed.

## Fail-Closed Rules

The coordinator blocks unknown actors, unknown capabilities, unknown actions,
missing governance metadata, raw payload metadata, and any execution request.

## Evidence

Evidence is deterministic, hash-only, redacted, and local. Raw payloads,
credentials, provider data, and production runtime data are forbidden.

## Remaining Gaps

- No live agent execution is implemented.
- Human approval remains external.
- This layer does not modify gateway or runtime enforcement behavior.
