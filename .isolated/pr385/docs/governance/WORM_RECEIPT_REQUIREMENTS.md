# WORM Receipt Requirements

Purpose: define the minimum receipt fields required for external WORM pilot evidence.

Runtime impact: none.

Certification impact: none.

## Required Receipt Fields

Every provider receipt must include:

- Provider receipt ID.
- Provider ID.
- Provider object ID.
- Provider storage location identifier.
- Receipt timestamp.
- SHA256 evidence hash.
- Retention class.
- Retention-until timestamp.
- Legal hold state.
- Immutable write proof.
- Provider audit reference.
- USBAY sealed archive ID.
- USBAY archive root hash.
- USBAY WORM storage plan ID.
- Export verification record ID.

## Integrity Requirements

The receipt must be hash-bound to the USBAY evidence object.

The receipt must be bound to the provider object ID.

The receipt must be bound to retention and legal hold evidence.

The receipt must be bound to an export verification record.

## Fail-Closed Conditions

Decision: BLOCKED when receipt integrity cannot be verified.

Decision: BLOCKED when the receipt hash does not match the USBAY evidence hash.

Decision: BLOCKED when the provider object ID is missing.

Decision: BLOCKED when receipt evidence cannot be mapped to a USBAY WORM storage plan.
