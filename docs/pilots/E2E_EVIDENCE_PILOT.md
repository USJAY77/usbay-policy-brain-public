# End-to-End Governance Evidence Lifecycle Pilot

Purpose: run one complete governance evidence path through the USBAY audit lifecycle without changing runtime behavior, creating AWS resources, committing credentials, committing private keys, making certification claims, or changing blocker status.

Runtime impact: none.

AWS resource creation: none.

Credentials committed: none.

Private keys committed: none.

Certification claim: none.

Blocker status change: none.

Default decision: BLOCKED.

Required governance rule:

- Evidence before claims.
- USBAY decides.
- Humans approve.
- Fail closed by default.

Allowed outcomes:

- APPROVED
- BLOCKED

## Lifecycle Overview

The pilot validates the complete evidence lifecycle:

1. Collect evidence package.
2. Validate evidence package.
3. Review validation result.
4. Sign reviewed evidence.
5. Timestamp signed evidence.
6. Archive evidence under WORM controls.
7. Export evidence bundle.
8. Verify exported bundle.
9. Run provider intake validation.

Euria or any external assistant may analyze evidence, identify gaps, and prepare review materials. Euria must not approve, execute, modify policy, bypass review, alter audit records, or override USBAY enforcement.

## Evidence Package

Required evidence package fields:

- Evidence package ID.
- Evidence source.
- Evidence collection timestamp.
- Evidence subject.
- Evidence hash.
- Chain-of-custody reference.
- Collection actor.
- Collection device or system identity.
- Scope boundary.

Required decision:

```text
BLOCKED
```

unless every required evidence package field exists and maps to a USBAY-controlled source.

## Validation Result

Required validation result fields:

- Validation result ID.
- Evidence package reference.
- Policy validation reference.
- Validation actor or validator identity.
- Validation timestamp.
- Validation decision.
- Missing evidence list.
- Invalid evidence list.
- Unsupported claim list.

Validation must fail closed if:

- Evidence is missing.
- Evidence hash is invalid.
- Policy reference is missing.
- Validation actor is missing.
- Validation result is not reproducible.

Required decision when validation fails:

```text
BLOCKED
```

## Review Result

Required review result fields:

- Review result ID.
- Validation result reference.
- Human reviewer reference.
- Review timestamp.
- Review decision.
- Review scope.
- Evidence references reviewed.
- Rejection reason when blocked.

Human approval is required before an approved outcome.

Human approval does not replace evidence, validation, signature, timestamp, archive, export, verification, or provider intake controls.

Required decision when review is missing:

```text
BLOCKED
```

## Signature Record

Required signature record fields:

- Signature record ID.
- Signed artifact reference.
- Signed artifact SHA256.
- Signature algorithm.
- Signature value.
- Public key reference.
- Public key SHA256.
- Signer identity.
- Signing policy reference.
- Previous signature record hash where applicable.

Private keys must not be stored in the repository.

Required decision when signature is missing or invalid:

```text
BLOCKED
```

## Timestamp Record

Required timestamp record fields:

- Timestamp record ID.
- Timestamp subject reference.
- Timestamp subject SHA256.
- RFC3161-compatible token hash.
- TSA policy identifier.
- TSA certificate hash.
- Timestamp UTC value.
- Previous timestamp record hash where applicable.

Required decision when timestamp is missing or invalid:

```text
BLOCKED
```

## WORM Archive Record

Required WORM archive record fields:

- Archive record ID.
- Archive provider reference.
- Archive object ID.
- Archive object version ID.
- Archive manifest SHA256.
- Retention mode.
- Retention until timestamp.
- Legal hold status.
- Immutability status.
- Provider write receipt hash.
- Retention evidence hash.
- Legal hold evidence hash.
- Export verification hash.

Required decision when archive evidence is missing, retention is incomplete, or immutability is unverified:

```text
BLOCKED
```

## Export Bundle

Required export bundle fields:

- Export bundle ID.
- Evidence package reference.
- Validation result reference.
- Review result reference.
- Signature record reference.
- Timestamp record reference.
- WORM archive record reference.
- Lineage record reference.
- Bundle manifest SHA256.
- Bundle verification result.

Required decision when export is missing, incomplete, or unverifiable:

```text
BLOCKED
```

## Lineage Record

Required lineage record fields:

- Lineage record ID.
- Evidence package reference.
- Validation result reference.
- Review result reference.
- Signature record reference.
- Timestamp record reference.
- WORM archive record reference.
- Export bundle reference.
- Previous lineage hash where applicable.
- Current lineage hash.

Required decision when lineage is missing, broken, or tampered:

```text
BLOCKED
```

## Provider Intake Result

Required provider intake result fields:

- Provider evidence package ID.
- Provider submission reference.
- Provider receipt hash.
- Chain-of-custody reference.
- Evidence manifest hash.
- Signature validation reference.
- Timestamp validation reference.
- Audit lineage reference.
- Review reference.
- Export reference.
- WORM archive reference.
- Provider intake decision.

Required decision when provider evidence is missing, invalid, or unverified:

```text
BLOCKED
```

## Approved Path

Outcome may be:

```text
APPROVED
```

only when every control is present and verified:

- Evidence package exists.
- Validation result passes.
- Human review approves.
- Signature record is present and valid.
- Timestamp record is present and valid.
- WORM archive record is present, retained, and immutable.
- Export bundle is present and verified.
- Lineage record links every lifecycle stage.
- Provider intake result is verified.
- Audit evidence record can be reconstructed from evidence.
- USBAY enforcement boundary is preserved.

USBAY decides the final state. Euria or any external assistant may not convert analysis into approval.

## Blocked Path

Outcome must be:

```text
BLOCKED
```

when any required control is:

- Missing.
- Invalid.
- Unsigned.
- Untimestamped.
- Unreviewed.
- Unarchived.
- Unexported.
- Unlinked.
- Hash-mismatched.
- Not lineage-bound.
- Not provider-verified.
- Outside approved scope.
- Dependent on unsupported claims.
- Dependent on private keys, credentials, secrets, or unapproved provider data.

## Fail-Closed Decision Matrix

| Missing or failed control | Required outcome |
| --- | --- |
| Evidence package missing | BLOCKED |
| Validation result missing or failed | BLOCKED |
| Human review missing | BLOCKED |
| Signature missing or invalid | BLOCKED |
| Timestamp missing or invalid | BLOCKED |
| WORM archive missing or unverified | BLOCKED |
| Export bundle missing or unverifiable | BLOCKED |
| Lineage record missing or broken | BLOCKED |
| Provider intake missing, invalid, or unverified | BLOCKED |
| Runtime authority requested outside USBAY | BLOCKED |
| Certification claim requested without evidence | BLOCKED |
| Blocker status change requested without governed evidence | BLOCKED |

## Pilot Audit Record

The pilot decision record must include:

- Actor.
- Device or system identity.
- Decision.
- Timestamp.
- Policy version.
- Evidence package reference.
- Validation result reference.
- Human review reference.
- Signature record reference.
- Timestamp record reference.
- WORM archive reference.
- Export bundle reference.
- Lineage record reference.
- Provider intake reference.

If any pilot audit field is missing:

```text
BLOCKED
```

## Governance Boundary

This pilot is documentation-only.

This pilot does not create provider resources.

This pilot does not store credentials.

This pilot does not store private keys.

This pilot does not modify runtime enforcement.

This pilot does not modify policy enforcement.

This pilot does not alter audit records.

This pilot does not make certification claims.

This pilot does not change blocker status.
