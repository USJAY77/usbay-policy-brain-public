# Governance Post-Quantum Renewal Planning

USBAY post-quantum renewal plans provide deterministic local planning records for future governance evidence record renewal. This layer does not perform PQC signing. It records and verifies the intended migration path before a future governed signing implementation exists.

## PQ Renewal Lifecycle

1. Verify the current evidence record chain.
2. Create a PQ renewal plan for the next append-only renewal slot.
3. Bind the plan to the evidence record ID, sealed archive ID, current hash algorithm, target hash algorithm, current signature family, target signature family, policy ID, retention label, and replay-binding hash.
4. Verify the plan before any future PQ renewal implementation consumes it.

## Algorithm Migration Model

Current records use `SHA256`. A PQ renewal plan must target a stronger governed hash algorithm such as `SHA3_512` or `SHAKE256_512`. Equal-strength or weaker targets fail closed as downgrade attempts.

## Signature-Family Transition Model

Allowed target signature families are `ML_DSA`, `SLH_DSA`, and `HYBRID_ED25519_ML_DSA`. The hybrid path lets future migrations retain Ed25519 continuity while adding ML-DSA evidence.

## Downgrade Prevention

Plans fail closed if the target hash algorithm is weaker, unchanged, ungoverned, or paired with an unapproved target signature family. Append-only position and planned renewal round must match the next evidence record slot.

## Future Integration

Future FIPS 204 and FIPS 205 integration should consume these plans, attach real PQ signatures through governed execution, and preserve the deterministic replay-binding model. No private keys, raw payloads, approval contents, or raw revocation material belong in these planning records.
