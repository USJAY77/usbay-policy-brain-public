# Runtime Coordinator

The Runtime Coordinator connects the local runtime design contracts into a
single metadata-only pipeline. It does not execute commands, start tmux, open
sockets, call providers, or activate production behavior.

## Connected Components

- Agent Runtime
- Execution Scheduler
- Event Bus
- Runtime Health
- Tmux supervisor metadata
- Gateway metadata
- Audit metadata

## Scheduler Contract

The scheduler contract accepts only these states:

- READY
- WAITING
- BLOCKED
- FAILED
- FINISHED

Unknown states fail closed.

## Event Routing Contract

Supported route labels are:

- validate
- publish
- subscribe
- audit
- fail_closed

Unknown routes are rewritten to `fail_closed` in the coordinator output and
the decision is blocked.

## Runtime Evidence

The coordinator emits hash-only evidence:

- runtime_id
- policy_hash
- orchestration_hash
- health_hash
- timestamp
- decision_hash

No raw payloads, credentials, provider data, or runtime artifacts are emitted.
The coordinator output always keeps `execution_allowed=false`,
`provider_execution=false`, and `production_activation=false`.
Human approval metadata remains external hash/reference material only and is
never fabricated by this layer. The coordinator does not emit any claim of live
runtime readiness.

## Fail-Closed Rules

The coordinator blocks when:

- runtime metadata is unknown
- required evidence is missing
- actor metadata is unknown
- decision metadata is missing
- scheduler state is invalid
- event bus state is invalid
- component health state is invalid
- provider execution or production activation is requested
- any required runtime component is unavailable
- execution is requested
- raw payload metadata is present

This layer is an integration contract, not a runtime execution engine.
