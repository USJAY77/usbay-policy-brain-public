# EURIA Pilot Activation Gateway Readiness

This contract is the Policy Brain-side handoff from a valid EURIA customer
onboarding `PILOT_READY` decision to an Enforcement Gateway authorization
request. It is intentionally narrow and metadata-only.

## Authority Model

EURIA remains intake and orchestration only:

- `EURIA_EXECUTION_AUTHORITY=false`
- `EURIA_POLICY_AUTHORITY=false`
- `EURIA_APPROVAL_AUTHORITY=false`
- `EURIA_DEPLOYMENT_AUTHORITY=false`

`PILOT_READY` is not execution authorization. Pilot readiness can request
gateway authorization but cannot grant it. Only an explicit governed Enforcement
Gateway authorization record can produce `EXECUTION_AUTHORIZED`.

## State Model

Supported activation states are:

- `PILOT_READY`
- `ACTIVATION_REQUESTED`
- `ACTIVATION_VALIDATING`
- `EXECUTION_AUTHORIZED`
- `BLOCKED`
- `EXPIRED`
- `REVOKED`

Unknown, malformed, stale, replayed, expired, revoked, mismatched, or
contradictory metadata blocks.

## TOCTOU Revalidation

The activation evaluator revalidates the current EURIA onboarding context
immediately before evaluating a gateway authorization record. A previously
valid readiness decision is insufficient if approval, policy, tenant,
environment, pilot, identity, verifier, attestation, challenge, nonce, or
evidence-chain metadata changed.

## Evidence

Activation evidence is hash/reference-only and includes the readiness decision
hash, activation request hash, policy hash, approval reference, pilot reference,
gateway decision reference, and evidence-chain reference. It must not contain
secrets, credentials, raw identity documents, private customer content,
private keys, tokens, or provider payloads.

## Cross-Repository Compatibility

The expected Enforcement Gateway input is the `PilotActivationRequest` metadata
package. The expected Enforcement Gateway output is a hash-only authorization
record containing:

- `gateway_authoritative=true`
- `decision=EXECUTION_AUTHORIZED`
- `execution_authorized=true`
- `gateway_decision_hash`
- `activation_request_hash`
- `readiness_decision_hash`
- `policy_hash`
- `tenant_reference`
- `environment_reference`

If the gateway is unavailable, indeterminate, mismatched, or non-authoritative,
the Policy Brain-side result remains `BLOCKED`.
