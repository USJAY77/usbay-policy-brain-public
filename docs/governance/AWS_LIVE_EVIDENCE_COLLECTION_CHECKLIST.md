# AWS Live Evidence Collection Checklist

Purpose: prepare the repository for collecting real AWS S3 Object Lock evidence required for BLOCKER-003 evaluation.

Runtime impact: none.

Gateway impact: none.

Policy enforcement impact: none.

AWS resource creation: prohibited by this checklist.

Provider credentials stored in repository: prohibited.

Certification claim: prohibited.

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Collection Boundary

This checklist defines the evidence that must be collected during a governed AWS Object Lock pilot.

This checklist does not create AWS resources.

This checklist does not store AWS credentials.

This checklist does not verify AWS Object Lock.

This checklist does not certify immutable storage.

This checklist does not close BLOCKER-003.

## Write Receipt Collection

Required write receipt evidence:

- Object Lock write receipt.
- AWS account boundary reference.
- AWS region.
- S3 bucket identifier.
- S3 object key.
- S3 object version ID.
- SHA256 evidence hash.
- USBAY sealed archive ID.
- USBAY archive root hash.
- USBAY WORM storage plan ID.
- Provider audit reference for the write event.

If write receipt evidence is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Retention Evidence Collection

Required retention evidence:

- Object Lock mode.
- Retention configuration evidence.
- Retention period input.
- Retain-until timestamp.
- Retention policy identifier or hash.
- Evidence that delete is denied during retention.
- Evidence that overwrite is denied during retention.
- Provider audit reference for retention configuration.

If retention evidence is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Legal Hold Evidence Collection

Required legal hold evidence:

- Legal hold status.
- Legal hold evidence.
- Legal hold timestamp if active.
- Legal hold authority reference if legal hold state changes.
- S3 object version ID bound to legal hold evidence.
- Provider audit reference for legal hold state.

If legal hold evidence is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Export Verification Collection

Required export verification evidence:

- Export verification record ID.
- Export verification evidence.
- Provider object hash.
- USBAY archive root hash.
- USBAY WORM storage plan ID.
- S3 object version ID.
- Verification actor.
- Verification timestamp.
- Provider audit reference for export or read verification.

If export verification evidence is missing or hash continuity fails:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Provider Audit Reference Collection

Provider audit references must bind to:

- Bucket Object Lock configuration.
- Object write event.
- Retention configuration event.
- Legal hold event.
- Delete-denial test.
- Overwrite-denial test.
- Export verification event.
- Provider outage fail-closed test, if performed.

If provider audit reference evidence is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Validation Workflow

Validation must confirm:

1. Every required evidence artifact exists.
2. Every artifact is redacted before repository storage.
3. No credentials, private keys, raw payloads, approval contents, or raw regulator exports are present.
4. S3 object version ID binds write, retention, legal hold, export verification, and provider audit evidence.
5. SHA256 evidence hash matches the USBAY archive root hash.
6. Retention evidence shows delete and overwrite denial during retention.
7. Legal hold evidence is present and bound to the object version when required.
8. Export verification binds AWS evidence to the USBAY WORM storage plan ID.
9. Provider audit references bind to each required event.
10. Missing or unverifiable evidence produces a blocked decision.

If any validation step fails:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Fail-Closed Decision Rules

If real AWS evidence is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

If any required evidence item is incomplete, unverifiable, unbound, hash-mismatched, unaudited, or not redacted:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

If AWS credentials or provider secrets appear in repository evidence:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

Human approval is not evidence.

Provider marketing material is not evidence.

Screenshots without audit binding are not evidence.

Only real provider evidence may support a future BLOCKER-003 status change.
