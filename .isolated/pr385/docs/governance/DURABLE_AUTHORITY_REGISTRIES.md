# Durable Governance Authority Registries

This layer provides durable, request-time-queryable governed authority state for
the Enforcement Gateway authorization consumer. It closes the authority-source
blocker without granting execution authority.

## Authority Boundary

The registries store and resolve governed authority metadata only:

- human approval
- activation
- challenge
- identity
- verifier
- attestation

Registry records do not authorize execution. Policy Brain remains
non-executing. EURIA remains non-authoritative for execution, policy, approval
and deployment. Only the Enforcement Gateway may produce final runtime
`ALLOW` or `BLOCK` after independent validation.

## Storage

Storage is append-only JSONL with a hash chain. Each mutation writes a
hash-only evidence event first, then appends the registry event. The registry is
safe to reopen after process restart; lookup replays the durable log and uses
the latest authoritative event for a reference. Revocation is final.

## Request-Time Interface

Gateway consumers should use:

- `resolve_human_approval(...)`
- `resolve_activation(...)`
- `resolve_challenge(...)`
- `resolve_identity(...)`
- `resolve_verifier(...)`
- `resolve_attestation(...)`

Every resolver returns one of `VALID`, `MISSING`, `REVOKED`, `EXPIRED`,
`MISMATCH`, `MALFORMED` or `UNKNOWN`. Unknown never becomes valid.

## Fail-Closed Rules

Missing, malformed, expired, revoked, stale, mismatched, contradictory,
unavailable or corrupted authority state resolves non-valid and must block
downstream execution. Evidence-write failure blocks mutation.

## Privacy

Records are reference/hash oriented. Do not store raw customer payloads,
secrets, credentials, private keys, access tokens, raw prompts, raw approvals,
or unnecessary personal data.

## Remaining Hardening Gap

`SIGNATURE_ANCHOR_REMAINING_GAP=HARDENING_GAP_NON_BLOCKING`. This registry
uses deterministic hash chaining and consumer validation; detached signature
anchoring remains a future hardening step.
