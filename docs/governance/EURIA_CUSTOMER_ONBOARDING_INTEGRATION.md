# EURIA Customer Onboarding Integration

The EURIA customer onboarding bridge converts a valid EURIA enterprise intake
request into USBAY customer onboarding readiness metadata. It is additive only:
it does not approve execution, create tenants, enroll devices, activate pilots,
or bypass the Enforcement Gateway.

## Authority Boundary

EURIA remains non-authoritative for USBAY governance decisions:

- `EURIA_EXECUTION_AUTHORITY=false`
- `EURIA_POLICY_AUTHORITY=false`
- `EURIA_APPROVAL_AUTHORITY=false`
- `EURIA_DEPLOYMENT_AUTHORITY=false`

The bridge never returns execution authorization. `onboarding_ready=true` only
means the metadata package is ready for a later governed gateway review.

## State Model

The bridge returns one of:

- `INTAKE_RECEIVED`
- `INTAKE_VALIDATED`
- `REVIEW_REQUIRED`
- `HUMAN_APPROVAL_PENDING`
- `HUMAN_APPROVED`
- `POLICY_VALIDATION_PENDING`
- `POLICY_VALIDATED`
- `ONBOARDING_PENDING`
- `IDENTITY_PENDING`
- `VERIFIER_PENDING`
- `ATTESTATION_PENDING`
- `PILOT_READY`
- `BLOCKED`
- `REVOKED`
- `EXPIRED`

Unknown, malformed, missing, contradictory, expired, replayed, revoked, or
tampered state returns `BLOCKED`, except for absent readiness artifacts that
produce the explicit non-authorizing pending state.

## Required Controls

`PILOT_READY` requires all of the following:

- EURIA intake contract validates.
- Human approval is present, unexpired, not revoked, and not AI-only.
- Human approval is request-, tenant-, environment-, policy-, and identity-bound
  where identity binding is present.
- Policy validation is authoritative, bound to the requested policy, and
  includes matching policy hash and registry hash references.
- Customer onboarding record evaluates through USBAY customer onboarding.
- Device identity is enrolled and bound to tenant and environment references.
- Verifier enrollment is present and bound to tenant and environment references.
- Challenge nonce is fresh and not replayed.
- Attestation binds the enrolled device to the enrolled verifier.
- Pilot status is not revoked and is bound to tenant, environment, and policy.
- Evidence references are hash-only, tamper-evident, and chain-verifiable when
  previous/current evidence hashes are supplied.

## Fail-Closed Rules

The bridge blocks when any authority flag is asserted, when evidence is
tampered, when sensitive data is present, or when an artifact is malformed.
It also blocks policy hash mismatches, wrong tenant or environment bindings,
wrong policy references, expired approvals, revoked approvals, replayed
approvals, replayed challenges, invalid attestations, registry mismatches,
evidence-chain mismatches, onboarding expiry, contradictory state, and pilot
revocation.

## Evidence

Bridge evidence is deterministic and hash-only. It contains request metadata,
tenant and environment references, policy reference, state, reason codes,
timestamp, intake contract hash, and bridge evidence hash. It must not contain
unredacted customer content, secrets, credentials, prompts, tokens, or
attestation payloads.

`PILOT_READY` is not execution authorization. Runtime execution remains under
the Enforcement Gateway authority and requires a separate governed runtime
decision.
