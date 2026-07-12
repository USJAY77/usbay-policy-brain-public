# USBAY Governance Event Bus

## Purpose

The Governance Event Bus models immutable append-only governance events. It is
an in-memory metadata contract only.

## Event Fields

Every event must include policy hash, tenant hash, evidence hash, correlation
ID, timestamp, actor, route, and decision ID.

Routes are explicitly governed by a fixed local allow-list. Unknown routes,
near matches, capitalization changes, socket-like labels, provider-like labels,
network-like labels, subprocess-like labels, background-job labels, and
production labels fail closed. Route validation is exact and deterministic; no
prefix, substring, wildcard, environment, provider discovery, or dynamic
fallback can widen the route registry.

## Safety Boundaries

- No sockets.
- No message broker.
- No network.
- No Redis.
- No Kafka.
- No execution.
- No route implies execution capability.
- Human approval remains external.

## Fail-Closed Rules

Events fail closed when required fields are missing, raw payload metadata is
present, execution is requested, or the route is absent from the governed
metadata-only route registry.

## Evidence

Events remain hash-only, redacted, deterministic, and append-only.

## Remaining Gaps

- No external event transport exists.
- No broker persistence exists.
