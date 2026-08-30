# Human Approval Gateway

The Human Approval Gateway is the PB-C2 Phase C metadata-only approval verifier.
It consumes PB-C1 Runtime Simulator output and an external human approval
reference by hash/reference only.

## Scope

The gateway validates approval metadata. It does not execute commands, mutate
policy, deploy, open sockets, start threads, start subprocesses, use Redis, use
Kafka, start brokers, start tmux, call providers, call APIs, contact networks,
or activate production.

Every output preserves:

- `execution_allowed = false`
- `provider_execution = false`
- `production_activation = false`
- `runtime_execution = false`
- `deployment_execution = false`
- `policy_mutation = false`
- `network_access = false`

## Supported States

- `APPROVAL_VALID`: approval metadata is internally consistent and in scope.
- `APPROVAL_REQUIRED`: approval reference, approval hash, or granted status is
  missing.
- `APPROVAL_EXPIRED`: approval metadata is no longer valid at the evaluation
  timestamp.
- `APPROVAL_BLOCKED`: tenant, policy, evidence, role, scope, simulator hash,
  schema, version, duplicate, replay, or execution metadata is invalid.
- `APPROVAL_FAILED_CLOSED`: malformed metadata or raw approval content is
  supplied.

`APPROVAL_VALID` is not authorization to execute. It is only a deterministic
metadata statement that the external approval reference passed validation.

## Required Metadata

The approval reference must include:

- component
- schema version
- output version
- approval reference
- approval hash
- approval status
- approver role hash
- scope hash
- tenant hash
- policy hash
- evidence hash
- simulator decision hash
- issued timestamp
- expiration timestamp
- hash algorithm

The simulator reference must identify `runtime_simulator`, be in `SIM_READY`,
and preserve hash-only, redacted, no-execution metadata.

## Fail-Closed Rules

The gateway blocks or fails closed for missing approval references, missing
simulator references, missing hashes, ungranted approval, wrong role, wrong
scope, expired approval, future timestamps outside tolerance, tenant mismatch,
policy mismatch, evidence mismatch, simulator hash mismatch, duplicate or
replayed approval references, malformed metadata, unknown metadata, unknown
components, unsupported schemas, unsupported versions, unsupported hash
algorithms, non-hash evidence, unredacted evidence, raw approval content, and any
execution-like flag.

## Evidence

Evidence remains deterministic, immutable, hash-only, and redacted. Raw approval
comments, names, emails, identity signatures, credentials, tokens, customer data,
policy payloads, evidence payloads, provider data, and free-form text are
forbidden.

## Remaining Gaps

- PB-C2 does not implement a controlled execution sandbox.
- Approval validity does not authorize execution.
- External human identity verification remains outside this local metadata
  gateway and must be provided as hash/reference-only evidence.
