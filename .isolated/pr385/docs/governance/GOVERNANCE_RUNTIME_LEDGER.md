# Governance Runtime Ledger

## Purpose

The Governance Runtime Ledger records governance decisions as immutable references. It is additive evidence infrastructure only. It does not change policy evaluation, approval validation, production readiness, regulator export, or runtime execution behavior.

## Ledger Schema

Each ledger entry contains only reference metadata:

- ledger ID
- append-only position
- timestamp
- tenant
- policy version
- validator
- decision
- failure code
- evidence ID
- audit hash
- previous hash
- correlation ID
- entry hash
- execution flags fixed to false

Raw payloads, approval contents, evidence bodies, secrets, credentials, tokens, private keys, certificates, and provider data are forbidden.

## Append Rules

Entries are appended after the existing ledger verifies. The first entry uses the genesis hash. Each later entry binds `previous_hash` to the prior entry hash.

The helper refuses to append if the existing ledger is malformed, reordered, tampered, or contains duplicates.

## Hash Rules

`ledger_id` is derived from the decision reference metadata, excluding append position and previous hash. `entry_hash` is derived from the full entry payload, including append position and previous hash.

This separates decision identity from chain placement while preserving tamper-evident chronology.

## Retention Assumptions

The current ledger is an in-memory/reference contract. Durable storage remains separate and should use existing append-only audit evidence persistence or future WORM storage integrations. No external service, database, message broker, tmux process, or production execution path is introduced.

## Relationship With Audit Evidence

The ledger consumes audit hashes and correlation IDs produced by the audit evidence and audit pipeline layers. It does not serialize the underlying evidence payload and does not authorize a decision because an audit hash exists.

## Relationship With Evidence Chain

Evidence-chain, WORM, sealed archive, signed bundle, and regulator export modules remain the durable/export-oriented evidence systems. The runtime ledger provides chronology for governance decisions by reference and can be consumed by those systems in later focused batches.

## Fail-Closed Behavior

The ledger fails closed for:

- missing context
- unsupported decisions
- malformed hashes
- duplicate entries
- reordered entries
- previous-hash mismatches
- tampered ledger IDs
- tampered entry hashes
- raw-data markers

All ledger outputs preserve:

- `execution_allowed=false`
- `provider_execution=false`
- `production_activation=false`
