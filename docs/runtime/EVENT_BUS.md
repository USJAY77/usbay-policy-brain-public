# USBAY Governance Event Bus

## Purpose

The Governance Event Bus models immutable append-only governance events. It is
an in-memory metadata contract only.

## Event Fields

Every event must include policy hash, tenant hash, evidence hash, correlation
ID, timestamp, actor, route, and decision ID.

## Safety Boundaries

- No sockets.
- No message broker.
- No network.
- No Redis.
- No Kafka.
- No execution.

## Fail-Closed Rules

Events fail closed when required fields are missing, raw payload metadata is
present, or execution is requested.

## Evidence

Events remain hash-only, redacted, deterministic, and append-only.

## Remaining Gaps

- No external event transport exists.
- No broker persistence exists.
