# Runtime Evidence Aggregator

## Purpose

The Runtime Evidence Aggregator creates deterministic, metadata-only evidence continuity across the approved Phase B runtime governance components. It aggregates existing evidence hashes and decision hashes only. It does not authorize runtime work and does not perform execution.

## Trust Boundary

The aggregator accepts evidence references only from these components, in this exact order:

1. `agent_runtime`
2. `runtime_coordinator`
3. `event_bus`
4. `runtime_health`
5. `execution_scheduler`

Unknown names, duplicates, near matches, case variants, prefixes, suffixes, whitespace variants, and missing components fail closed.

## Required Metadata

Each component reference must include:

- `component`
- `evidence_hash`
- `policy_hash`
- `tenant_hash`
- `decision_hash`
- `timestamp`
- `schema_version`
- `evidence_version`
- `hash_algorithm`
- `redacted`
- `hash_only`
- `execution_allowed`
- `provider_execution`
- `production_activation`

Hashes must use canonical `sha256:<64 lowercase hex>` form. The only supported hash algorithm is `sha256`.

## Canonical Ordering And Serialization

Aggregation uses the fixed component order above. The implementation normalizes metadata into canonical dictionaries and serializes with sorted JSON keys and compact separators before SHA-256 hashing. The result does not depend on dictionary insertion order, local time, random values, generated identifiers, or external state.

## Success State

A successful aggregation returns:

- `status: EVIDENCE_AGGREGATED`
- `denial_code: null`
- `hash_only: true`
- `redacted: true`
- `execution_allowed: false`
- `provider_execution: false`
- `production_activation: false`

The output contains only component identifiers, hashes, schema/version metadata, timestamps, denial metadata, and remaining gap labels.

## Fail-Closed Denial States

The aggregator blocks deterministic aggregation for missing, unknown, duplicated, malformed, mismatched, unredacted, execution-enabled, provider-enabled, production-enabled, raw, or sensitive evidence metadata. Denials return `EVIDENCE_BLOCKED` and a fixed denial code.

## Security Boundaries

This component contains no runtime execution, task execution, worker queue, subprocess spawning, shell command execution, sockets, networking, HTTP/API/provider/LLM calls, threads, async execution, Redis, Kafka, brokers, databases, tmux execution, credential access, or production activation.

## Evidence Minimization

Evidence is hash-only and redacted. Raw customer content, credentials, provider data, prompts, personal data, and runtime artifacts must not be supplied or logged.

## Human Oversight

Human approval remains external to this component. Aggregated metadata is not customer-visible approval, runtime readiness, or production authorization.

## Remaining Gaps

- Human approval remains an external hash/reference.
- Aggregation does not prove production readiness.
- Aggregation does not authorize execution.
- Merge and deployment review remain separate governed processes.
