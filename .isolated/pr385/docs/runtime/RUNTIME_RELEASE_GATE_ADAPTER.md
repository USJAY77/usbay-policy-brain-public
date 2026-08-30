# Runtime Release Gate Adapter

The Runtime Release Gate Adapter is a Phase B metadata-only contract. It
translates approved runtime governance outputs into deterministic release
readiness metadata without authorizing execution, deployment, policy changes, or
production activation.

## Approved Inputs

The adapter consumes only hash/reference metadata from these Phase B components,
in this fixed order:

1. `agent_runtime`
2. `runtime_coordinator`
3. `event_bus`
4. `runtime_health`
5. `execution_scheduler`
6. `runtime_evidence_aggregator`
7. `runtime_policy_binding`
8. `runtime_approval_gate`
9. `runtime_replay_verifier`

No dynamic discovery, aliases, prefix matching, suffix matching, or
case-insensitive component matching is permitted.

## Release Metadata

Successful validation returns `RELEASE_READY_METADATA`. This is not deployment
approval. It only confirms that the supplied governance metadata is internally
consistent and ready for human review.

All outputs preserve:

- `execution_allowed = false`
- `provider_execution = false`
- `production_activation = false`

## Fail-Closed Rules

The adapter returns `RELEASE_BLOCKED` for missing evidence, missing approval,
replay mismatch, policy mismatch, tenant mismatch, evidence mismatch, malformed
metadata, duplicate metadata, invalid chronology, unsupported schema,
unsupported version, unsupported hash algorithm, unknown component, unknown
stage, unknown metadata, invalid hashes, non-hash-only evidence, unredacted
evidence, enabled execution flags, provider execution, production activation, or
sensitive-data markers.

## Safety Boundaries

The adapter does not execute work. It does not start threads, async tasks,
subprocesses, sockets, tmux sessions, Redis, Kafka, brokers, HTTP/API/LLM calls,
provider integrations, credential access, deployment, policy mutation, or
production activation.

## Evidence

Evidence remains deterministic, hash-only, redacted, and local. Raw payloads,
credentials, provider data, customer data, and approval contents are forbidden.
The evidence fixture records only fixed component identities, safe flags,
sample hashes, denial codes, and remaining governance gaps.

## Remaining Gaps

- Release metadata does not authorize execution.
- Human review remains required before release decisions can be customer-facing.
- Deployment and merge authorization remain external to this adapter.
