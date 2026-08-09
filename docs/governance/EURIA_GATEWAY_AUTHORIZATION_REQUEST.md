# EURIA Gateway Authorization Request Contract

This contract is the Policy Brain-side handoff from a fully revalidated EURIA
pilot activation request to the Enforcement Gateway. It creates a deterministic,
hash-bound authorization request package only.

Creation of a Gateway authorization request does not authorize execution.

Execution remains blocked until the Enforcement Gateway independently validates
the request and returns an explicit governed authorization decision.

## Authority Model

EURIA remains intake and orchestration only:

- `EURIA_EXECUTION_AUTHORITY=false`
- `EURIA_POLICY_AUTHORITY=false`
- `EURIA_APPROVAL_AUTHORITY=false`
- `EURIA_DEPLOYMENT_AUTHORITY=false`

Policy Brain remains non-executing:

- `POLICY_BRAIN_EXECUTION_AUTHORITY=false`
- `PILOT_READY != EXECUTION_AUTHORIZED`
- `ACTIVATION_VALIDATED != EXECUTION_AUTHORIZED`
- `GATEWAY_REQUEST_CREATED != EXECUTION_AUTHORIZED`

Only the Enforcement Gateway may return the final runtime `ALLOW` or `BLOCK`
decision.

## Revalidation

Immediately before a Gateway authorization request is created, the evaluator
revalidates the current activation inputs through the existing EURIA pilot
activation readiness evaluator. Mutable approval, policy, tenant, environment,
pilot, identity, verifier, attestation, challenge, nonce, and evidence-chain
metadata must still match.

Any missing, malformed, stale, expired, revoked, replayed, mismatched,
tenant-invalid, environment-invalid, policy-invalid, identity-invalid,
verifier-invalid, attestation-invalid, challenge-invalid, or evidence-invalid
state blocks request creation.

## Request Integrity

The request uses the repository canonical hashing contract. The request hash
binds the contract version, tenant, environment, policy, activation request,
readiness decision, identity, verifier, attestation, challenge, nonce, evidence,
and Gateway consumer contract version.

The request is metadata-only and hash/reference-only. It must not contain raw
customer payloads, credentials, secrets, private keys, tokens, private customer
content, model conversation content, or unrestricted prompts.

## Gateway Compatibility

The expected Enforcement Gateway boundary receives
`usbay.euria.gateway_authorization_request.v1` and independently evaluates it
as `usbay.enforcement_gateway.authorization_request.v1`.

Policy Brain never converts this request into a runtime allow decision. If the
Gateway is unavailable, incompatible, indeterminate, or rejects the request,
execution remains blocked.
