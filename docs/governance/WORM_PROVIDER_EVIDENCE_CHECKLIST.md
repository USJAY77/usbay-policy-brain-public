# WORM Provider Evidence Checklist

Purpose: define evidence required before any external WORM provider can be considered beyond pilot evaluation.

Runtime impact: none.

Certification impact: none.

## Provider Evidence

Required evidence:

- Provider name.
- Provider account, project, subscription, or tenant boundary.
- Provider storage location identifier.
- Provider object ID.
- Provider immutable write receipt.
- Provider audit receipt.
- Retention class.
- Retention-until timestamp.
- Legal hold state.
- SHA256 evidence hash.
- Export verification record.

## Verification Evidence

Required verification:

- Provider receipt binds to USBAY sealed archive ID.
- Provider object hash matches USBAY SHA256 evidence hash.
- Retention evidence is present and verified.
- Legal hold evidence is present and verified.
- Delete attempt is denied.
- Overwrite attempt is denied.
- Provider outage fails closed.

## Blocked Conditions

Decision: BLOCKED when any required evidence is missing.

Decision: BLOCKED when provider capability is not verified by evidence.

Decision: BLOCKED when human approval is offered instead of provider evidence.

Decision: BLOCKED when diagnostics include credentials, secrets, raw payloads, approval contents, private keys, or raw regulator exports.
