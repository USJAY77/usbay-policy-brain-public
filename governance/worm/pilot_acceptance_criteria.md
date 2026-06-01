# External WORM Pilot Acceptance Criteria

Purpose: define acceptance criteria for the USBAY external WORM pilot framework.

Runtime impact: none.

Production activation: prohibited.

Certification claim: prohibited.

Regulator-grade assertion: prohibited.

## Required Pilot Evidence

The pilot remains BLOCKED until all evidence exists:

- Provider write receipt.
- Provider object ID.
- Retention evidence.
- Legal hold evidence.
- Immutable write evidence.
- Audit receipt.
- Export verification evidence.
- SHA256 evidence hash continuity.

## Acceptance Criteria

The pilot may be marked `PILOT_VERIFIED` only when:

- Provider write receipt exists.
- Retention evidence exists.
- Legal hold evidence exists.
- Immutable write proof exists.
- Export verification evidence exists.
- Provider audit receipt exists.
- SHA256 evidence hash matches the USBAY evidence hash.
- Delete attempt is denied.
- Overwrite attempt is denied.
- Provider outage fails closed.
- Diagnostics remain redacted and hash-only.

## Failure Criteria

The pilot must remain `BLOCKED` when:

- Any required evidence is missing.
- Provider capabilities are not verified by evidence.
- Provider receipt cannot be bound to USBAY evidence identifiers.
- Retention evidence is absent or mismatched.
- Legal hold evidence is absent or mismatched.
- Immutable write proof is absent.
- Export verification fails.
- Provider outage prevents verification.
- Delete or overwrite succeeds.
- Any credential, secret, raw payload, approval content, or raw regulator export appears in evidence.

Failure decision:

Decision: BLOCKED.

## Governance Constraints

Human approval is not evidence.

Provider marketing material is not evidence.

Local WORM readiness is not external WORM provider evidence.

No pilot result may close BLOCKER-003 without provider evidence, test evidence, audit evidence, and certification lifecycle review.
