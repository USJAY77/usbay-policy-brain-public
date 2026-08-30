# WORM Retention Requirements

Purpose: define minimum retention and legal hold requirements for the external WORM pilot framework.

Runtime impact: none.

Certification impact: none.

## Retention Requirements

External WORM evidence must include:

- Retention class.
- Retention-until timestamp.
- Retention policy identifier or hash.
- Provider retention evidence.
- Evidence that delete is denied during retention.
- Evidence that overwrite is denied during retention.

## Legal Hold Requirements

External WORM evidence must include:

- Legal hold state.
- Legal hold timestamp if legal hold is active.
- Legal hold authority reference if legal hold state changes.
- Evidence that deletion is denied while legal hold is active.

## Fail-Closed Conditions

Decision: BLOCKED when retention evidence is missing.

Decision: BLOCKED when legal hold evidence is missing.

Decision: BLOCKED when retention class cannot be mapped to USBAY governance retention.

Decision: BLOCKED when delete or overwrite is allowed during retention.

Decision: BLOCKED when human approval is used as a substitute for provider retention or legal hold evidence.
