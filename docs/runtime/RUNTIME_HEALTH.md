# USBAY Runtime Health Manager

## Purpose

The Runtime Health Manager evaluates local metadata for runtime readiness. It
does not start monitoring daemons, background loops, tmux sessions, sockets, or
external checks.

## States

- `HEALTHY`
- `DEGRADED`
- `BLOCKED`
- `UNKNOWN`

## Checks

- policy availability
- audit readiness
- tmux availability metadata
- scheduler readiness
- event bus readiness
- agent runtime readiness

## Fail-Closed Rules

Missing governance metadata, missing policy availability, or missing audit
readiness blocks the health decision. Unknown tmux metadata returns `UNKNOWN`.
Other unavailable local components degrade the health state.

## Evidence

Health output is deterministic, hash-only, redacted, local, and metadata-only.

## Remaining Gaps

- No monitoring daemon is implemented.
- No polling loop is implemented.
- No production readiness claim is made.
