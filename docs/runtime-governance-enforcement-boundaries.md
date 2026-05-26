# USBAY Runtime Governance Enforcement Boundaries

This document describes the runtime hardening boundary for the USBAY gateway. It documents enforcement behavior only; it does not add new governance architecture scaffolding, external services, production credentials, telemetry, OAuth, raw media handling, or network dependencies.

## Runtime Source of Truth

The gateway treats backend runtime evidence as authoritative. Requests are blocked when decision evidence, replay evidence, policy evidence, revocation state, or runtime attestation cannot be verified locally.

## Enforced Controls

- Persistent nonce replay protection: executed nonces are stored in the configured nonce store and are rejected on reuse, including after a local gateway restart using the same store path.
- Token and timestamp windows: decisions must remain inside their signed expiry window, and request timestamps must remain inside the replay policy window.
- Policy-version lock: the execution payload must match the policy version and policy hash captured when the decision was created.
- Revocation validation: revoked runtime state, policy hash, or policy version blocks execution.
- Attestation freshness: signed runtime attestation must be present, signature-valid, policy-bound, and within the configured max age.
- Missing or malformed evidence: missing decision evidence, malformed runtime evidence, missing attestation, stale attestation, or unverifiable evidence fails closed.

## Fail-Closed Behavior

The gateway returns HTTP 403 for invalid runtime evidence. Errors are reason-coded and audit events remain hash-first and sanitized. Raw payloads, private key material, tokens, secrets, and personal data are not logged.

## Configuration

- `USBAY_RUNTIME_ATTESTATION_MAX_AGE_SECONDS`: maximum signed attestation age. Defaults to 14 days for local pilot runtime compatibility.
- `USBAY_REVOKED_POLICY_HASHES`: comma-separated policy hashes that must not execute.
- `USBAY_REVOKED_POLICY_VERSIONS`: comma-separated policy versions that must not execute.
- `USBAY_RUNTIME_REVOCATION_STATE`: when set to `REVOKED`, `FROZEN`, `BLOCKED`, or `DISABLED`, execution fails closed.

## Non-Goals

This hardening does not add production signing keys, HSM integration, OAuth, telemetry services, external network calls, raw media handling, or new governance architecture layers. Production deployment still requires human-owned policy, key custody, runtime attestation authority, and operational review.
