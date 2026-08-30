# Governance PQ Runtime Verification

USBAY PQ runtime verification records are deterministic governance gates for future post-quantum verification. This layer does not implement ML-DSA, SLH-DSA, or hybrid verification yet. It proves that even stub verification can only execute after an explicit USBAY policy decision allows it.

## Governance-Gated Lifecycle

1. Verify the PQ renewal plan.
2. Require `verifier_mode=STUB_ONLY`.
3. Require a policy decision ID and `policy_decision=ALLOW`.
4. Bind the runtime record to the PQ renewal plan, evidence record, sealed archive, target hash algorithm, target signature family, validation policy, and retention label.
5. Verify the runtime record before any future PQ verification code path consumes it.

## STUB_ONLY Verifier Model

`STUB_ONLY` is the only allowed mode. It is a placeholder proving governance routing and fail-closed behavior. Live PQC verification modes must be added later through explicit governance review.

## Policy Approval Model

The runtime record fails closed unless policy metadata is present and the decision is `ALLOW`. `DENY`, missing decision IDs, invalid policy IDs, unsupported verifier modes, replayed records, and append-only mismatches are rejected.

## Future Integration Paths

Future FIPS 204 ML-DSA, FIPS 205 SLH-DSA, and hybrid Ed25519 plus ML-DSA verification must use this governance gate before execution. Private keys, raw payloads, approval contents, raw OCSP/CRL material, and generated runtime artifacts must never be added to these records.
