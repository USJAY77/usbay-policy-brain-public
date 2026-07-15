# Runtime Policy Binding

## Purpose

Runtime Policy Binding verifies that approved Phase B runtime evidence belongs to one governed policy, tenant, runtime version, and decision chain. The component is metadata-only and does not authorize or perform runtime execution.

## Approved Evidence Sources

The binding accepts references only from this fixed component order:

1. `agent_runtime`
2. `runtime_coordinator`
3. `runtime_health`
4. `event_bus`
5. `execution_scheduler`
6. `runtime_evidence_aggregator`

Unknown names, duplicates, missing dependencies, case variants, prefixes, suffixes, and near matches fail closed.

## Required Metadata

Each evidence reference must include:

- `component`
- `evidence_hash`
- `policy_hash`
- `tenant_hash`
- `decision_hash`
- `previous_decision_hash`
- `schema_version`
- `runtime_version`
- `hash_algorithm`
- `hash_only`
- `redacted`
- `execution_allowed`
- `provider_execution`
- `production_activation`

Hashes must use canonical `sha256:<64 lowercase hex>` form.

## Verification Rules

Runtime Policy Binding validates:

- policy hash equality
- tenant hash equality
- aggregated evidence hash equality
- fixed component membership
- fixed component ordering
- schema version equality
- runtime version equality
- decision hash continuity
- hard-false execution flags
- hash-only and redacted evidence

Missing, duplicated, malformed, mismatched, unredacted, non-hash-only, execution-enabled, provider-enabled, or production-enabled metadata returns `POLICY_BLOCKED`.

## Security Boundaries

This component contains no runtime action execution, subprocess spawning, sockets, networking, HTTP/API/provider/LLM calls, threads, async execution, Redis, Kafka, brokers, databases, tmux execution, credential access, or production activation.

## Evidence Minimization

Outputs contain component identifiers, hashes, schema/runtime versions, denial metadata, and remaining gap labels only. Raw payloads, credentials, provider data, prompts, personal data, policy contents, and tenant contents must not be supplied or logged.

## Human Oversight

Human approval remains outside this component as a governed hash/reference. A successful binding is evidence continuity only, not deployment approval or customer-visible runtime readiness.

## Remaining Gaps

- Human approval remains external.
- Binding does not authorize runtime execution.
- Merge and deployment review remain separate governed processes.
