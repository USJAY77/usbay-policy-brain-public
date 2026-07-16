# Runtime Replay Verifier

## Purpose

Runtime Replay Verifier deterministically reconstructs previously recorded runtime governance decisions from hash-only Phase B metadata. It provides replay evidence only. It does not execute, dispatch, approve, activate, retry, schedule, call providers, or communicate over a network.

## Approved Evidence Sources

The verifier accepts metadata references only from this fixed order:

1. `agent_runtime`
2. `runtime_coordinator`
3. `event_bus`
4. `runtime_health`
5. `execution_scheduler`
6. `runtime_evidence_aggregator`
7. `runtime_policy_binding`
8. `runtime_approval_gate`

Unknown, missing, duplicated, or reordered component references fail closed.

## Replay Request Contract

Replay requests must include:

- `replay_id`
- `original_decision_id`
- `actor`
- `action`
- `policy_hash`
- `tenant_hash`
- `evidence_hash`
- `approval_hash`
- `decision_hash`
- `previous_decision_hash`
- `timestamp`
- `original_timestamp`
- `schema_version`
- `evidence_version`
- `hash_algorithm`
- `expected_outcome`
- `execution_allowed`
- `provider_execution`
- `production_activation`
- `redacted`
- `hash_only`
- `component_references`
- `recorded_replay_hash`

Unknown fields fail closed. Hashes must use canonical `sha256:<64 lowercase hex>` form.

## Validation Rules

The verifier validates:

- exact field membership
- fixed outcome membership
- fixed component ordering
- canonical SHA-256 formatting
- policy, tenant, evidence, approval, and decision continuity
- previous-decision linkage
- timestamp format and chronology
- schema and evidence versions
- recorded replay hash reconstruction
- expected outcome consistency
- hash-only and redacted metadata
- hard-false execution flags

Ambiguous, malformed, mismatched, stale, reordered, omitted, duplicated, non-redacted, non-hash-only, or execution-like metadata returns deterministic denial evidence.

## Security Boundaries

This component contains no runtime execution, worker queues, threads, async execution, subprocesses, process spawning, sockets, networking, HTTP/API/provider/LLM calls, Redis, Kafka, brokers, tmux, credentials, secrets, dynamic imports, `eval`, `exec`, production activation, merge authorization, or deployment authorization.

## Evidence Minimization

Outputs contain only component identifiers, hashes, schema/version labels, replay status, denial labels, and remaining gap labels. Raw prompts, approval contents, credentials, provider data, and sensitive human data are rejected.

## Remaining Gaps

- Replay verification does not authorize execution.
- Replay records remain external inputs.
- Human review remains required before merge or deployment.
