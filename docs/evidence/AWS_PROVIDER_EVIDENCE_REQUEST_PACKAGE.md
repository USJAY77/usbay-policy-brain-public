# AWS Provider Evidence Request Package

Purpose: define the exact package used to request AWS S3 Object Lock provider evidence for BLOCKER-003 assessment.

Runtime impact: none.

Gateway impact: none.

Policy enforcement impact: none.

AWS resource creation: prohibited by this request package.

Provider credentials stored in repository: prohibited.

Provider verification claim: prohibited.

Certification claim: prohibited.

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Request Template

Request title:

AWS S3 Object Lock Evidence Request For USBAY BLOCKER-003 Assessment.

Requested provider:

AWS S3 Object Lock.

Requested evidence purpose:

Provide redacted, audit-bound evidence required to assess whether external WORM evidence exists for USBAY BLOCKER-003.

Required response boundary:

- Do not provide AWS credentials.
- Do not provide provider secrets.
- Do not provide private keys.
- Do not provide raw governance payloads.
- Do not provide approval contents.
- Do not provide raw regulator exports.
- Do not assert USBAY certification status.
- Do not assert BLOCKER-003 closure.

Required response decision if evidence cannot be provided:

Decision: BLOCKED.

Reason: Information not provided.

## Required Artifacts List

The provider evidence response must include:

- Object Lock write receipt.
- S3 bucket identifier.
- S3 object key.
- S3 object version ID.
- Object Lock mode.
- Retention configuration evidence.
- Retain-until timestamp.
- Legal hold evidence.
- Legal hold status.
- Export verification record.
- Provider audit reference.
- Delete-denial evidence during retention.
- Overwrite-denial evidence during retention.
- Provider outage fail-closed evidence, if tested.
- SHA256 evidence hash.
- USBAY archive root hash.
- USBAY WORM storage plan ID.

If any required artifact is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Naming Conventions

Evidence artifacts must use deterministic names:

- `object_lock_write_receipt.json`
- `retention_configuration_evidence.json`
- `legal_hold_evidence.json`
- `export_verification_record.json`
- `provider_audit_reference.md`
- `evidence_manifest.json`
- `chain_of_custody.json`
- `artifact_hashes.json`
- `review_decision.md`

Names must be stable across submission, validation, review, and audit packaging.

If evidence names are missing, ambiguous, duplicated, or inconsistent:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Delivery Requirements

Evidence delivery must include:

- Redacted evidence package.
- Evidence manifest.
- Artifact hash list.
- Chain-of-custody record.
- Provider audit references.
- Submission actor.
- Submission timestamp.
- Source system.
- Redaction status.
- Package identifier.

Evidence delivery must not include:

- AWS access key ID.
- AWS secret access key.
- AWS session token.
- Provider credentials.
- Private keys.
- Raw governance payloads.
- Approval contents.
- Raw regulator exports.

If evidence delivery includes prohibited content:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Hash Requirements

Hash requirements:

- Every artifact must include a SHA256 hash.
- Hashes must be calculated after redaction.
- Artifact hashes must be stored in `artifact_hashes.json`.
- Aggregate package hash must be recorded.
- Provider object hash must match the submitted SHA256 evidence hash.
- SHA256 evidence hash must match the USBAY archive root hash.
- Export verification record must bind hash continuity to the USBAY WORM storage plan ID.

If any hash is missing or mismatched:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Chain-Of-Custody Requirements

The chain-of-custody record must include:

- Package identifier.
- Artifact names.
- Artifact hashes.
- Collection actor.
- Collection timestamp.
- Redaction actor.
- Redaction timestamp.
- Submission actor.
- Submission timestamp.
- Review actor.
- Review timestamp.
- Evidence status.
- Decision status.

The chain-of-custody record must preserve chronology and bind every artifact to the package identifier.

If chain-of-custody is missing, incomplete, conflicting, or not chronological:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Rejection Criteria

Reject the provider evidence request response when:

- Required artifact is missing.
- Required naming convention is not followed.
- Required delivery metadata is missing.
- Required hash is missing or mismatched.
- Chain-of-custody metadata is missing, incomplete, conflicting, or not chronological.
- Provider audit reference is missing.
- Evidence cannot be bound to the S3 object version ID.
- Evidence cannot be bound to USBAY archive or WORM storage identifiers.
- Prohibited content is present.
- Human approval is offered as evidence.
- Provider marketing material is offered as evidence.
- Notion status text is offered as evidence.
- Certification status is asserted by the provider response.
- BLOCKER-003 closure is asserted by the provider response.

Rejection outcome:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Review Package Requirements

The review package must include:

- Provider evidence request.
- Provider evidence response.
- Evidence manifest.
- Artifact hash list.
- Chain-of-custody record.
- Validation checkpoint results.
- Rejection record, if applicable.
- Reviewer decision.

Allowed reviewer decisions:

- BLOCKED.
- READY_FOR_BLOCKER_003_REASSESSMENT.

`READY_FOR_BLOCKER_003_REASSESSMENT` is not a certification claim and does not close BLOCKER-003.

## Audit Package Requirements

The audit package must include:

- Evidence package manifest.
- Required artifact list.
- Received artifact list.
- Missing artifact list.
- Artifact hash list.
- Aggregate package hash.
- Chain-of-custody record.
- Provider audit references.
- Validation results.
- Reviewer decision.
- Rejection rationale, if applicable.

If any audit package requirement is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Request Package Boundary

This request package does not create AWS resources.

This request package does not store credentials.

This request package does not verify AWS.

This request package does not certify immutable storage.

This request package does not close BLOCKER-003.

Only evidence may support a future BLOCKER-003 reassessment.
