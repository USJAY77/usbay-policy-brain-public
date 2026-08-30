# PB-1L Governance Release Candidate Evidence Lock

PB-1L implements the approved PB-1L specification as a metadata-only release-candidate evidence lock verifier. It validates that PB-1K approval evidence closure output, release-candidate references, approval references, audit references, rollback references, replay metadata, evidence chronology, tenant references, policy references, and validation metadata align as one deterministic package for human review.

PB-1L SHALL NOT authorize runtime execution. It does not approve a release, deploy software, call providers, activate production, mutate policy, mutate runtime state, execute rollback, or replace the gateway.

## Inputs

PB-1L consumes only supplied metadata and hash/reference values:

- PB-1K decision and hash references
- release-candidate intent and evidence references
- external human approval references
- approval evidence references
- audit chain references
- evidence chain and chronology references
- rollback plan and evidence references
- replay metadata references
- validation evidence references
- tenant, policy, and correlation references

Raw payloads, prompts, provider responses, credentials, approval contents, tokens, cookies, private keys, personal data, environment dumps, runtime artifacts, and secret values are rejected.

## Decisions

PB-1L returns only:

- `READY`
- `READY_WITH_RESTRICTIONS`
- `BLOCKED`

`READY` means all required release-candidate evidence lock metadata validates and every execution safety flag remains false. `READY_WITH_RESTRICTIONS` means the same lock validates with explicit governed restriction metadata by reference only. `BLOCKED` is returned for every unknown, missing, malformed, stale, unsupported, inconsistent, sensitive, execution-shaped, replayed, duplicated, or unverifiable input.

## Safety Flags

Every PB-1L decision preserves:

- execution_allowed=false
- provider_execution=false
- production_activation=false
- deployment_authorized=false
- runtime_mutation=false
- policy_mutation=false

PB-1L metadata must never be interpreted as deployment approval, runtime authorization, provider readiness, production readiness, legal certification, compliance certification, or release approval.

## Rollback

PB-1L rollback is isolated to the PB-1L implementation commit. Reverting PB-1L removes release-candidate evidence lock verification metadata only and does not alter PB-1B through PB-1K behavior.
