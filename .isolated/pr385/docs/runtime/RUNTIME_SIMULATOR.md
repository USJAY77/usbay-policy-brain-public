# Runtime Simulator

The Runtime Simulator is the PB-C1 Phase C metadata-only simulator. It consumes
Phase B Runtime Release Gate Adapter output by hash/reference only and produces
deterministic simulation readiness metadata.

## Scope

The simulator does not execute work. It does not mutate state, deploy, change
policy, call providers, open sockets, start threads, start subprocesses, use
Redis, use Kafka, start brokers, start tmux, contact networks, or activate
production.

All outputs preserve:

- `execution_allowed = false`
- `provider_execution = false`
- `production_activation = false`

## Supported States

- `SIM_READY`: release metadata is internally consistent and has an approval
  hash reference.
- `SIM_REVIEW_REQUIRED`: release metadata is otherwise valid but lacks the
  external human approval reference.
- `SIM_BLOCKED`: required metadata, hashes, schema, versions, tenant, policy, or
  predecessor references are invalid.
- `SIM_FAILED_CLOSED`: malformed or sensitive metadata is supplied.

## Required Input

The simulator accepts a request containing only redacted metadata:

- simulation id
- policy hash
- tenant hash
- evidence hash
- release readiness hash
- approval hash
- simulation mode
- schema version
- simulator version
- release metadata reference
- safety flags

The release metadata reference must identify `runtime_release_gate_adapter` and
must use Phase B release-gate schema and output versions.

## Fail-Closed Rules

The simulator blocks or fails closed for missing metadata, invalid schema,
missing predecessor hash, unknown component, unsupported version, cross-tenant
metadata, policy mismatch, malformed metadata, unknown metadata, invalid hashes,
unsupported hash algorithm, non-hash-only evidence, unredacted evidence,
execution flags, provider execution flags, production activation flags, and
sensitive-data markers.

## Evidence

Evidence remains hash-only, redacted, deterministic, local, and immutable. Raw
payloads, credentials, prompts, customer data, provider data, private keys,
tokens, and secrets are forbidden.

## Remaining Gaps

- PB-C1 does not implement a controlled execution sandbox.
- Simulation readiness does not authorize execution.
- Human approval remains external and mandatory before any future sandbox
  action.
