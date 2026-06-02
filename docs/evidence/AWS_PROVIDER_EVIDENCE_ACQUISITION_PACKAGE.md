# AWS Provider Evidence Acquisition Package

Purpose: define exactly what AWS Object Lock provider evidence must be requested, received, validated, and reviewed before BLOCKER-003 may be reassessed.

Runtime impact: none.

Gateway impact: none.

Policy enforcement impact: none.

AWS resource creation: prohibited by this package.

Provider credentials stored in repository: prohibited.

Provider verification claim: prohibited.

Certification claim: prohibited.

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Required Provider Artifacts

The provider evidence request must require:

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

If any required provider artifact is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Submission Format

Provider evidence must be submitted as a redacted evidence package.

Required submission fields:

- Package identifier.
- Submission actor.
- Submission timestamp.
- Provider identifier.
- AWS account boundary reference.
- AWS region.
- Evidence artifact list.
- Artifact hash list.
- Chain-of-custody metadata.
- Provider audit references.
- Redaction attestation.

Submission must not include:

- AWS access key ID.
- AWS secret access key.
- AWS session token.
- Provider credentials.
- Private keys.
- Raw governance payloads.
- Approval contents.
- Raw regulator exports.

If prohibited content is present:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Hash Verification Requirements

Hash verification must prove:

- Every submitted artifact has a SHA256 hash.
- Hashes are calculated after redaction.
- Aggregate package hash exists.
- Provider object hash matches the submitted SHA256 evidence hash.
- Submitted SHA256 evidence hash matches USBAY archive root hash.
- Export verification record binds hash continuity to USBAY WORM storage plan ID.

If any hash is missing or mismatched:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Chain-Of-Custody Requirements

Every evidence artifact must include:

- Collection actor.
- Collection timestamp.
- Source system.
- Provider evidence type.
- Redaction actor.
- Redaction timestamp.
- Submission actor.
- Submission timestamp.
- Review actor.
- Review timestamp.
- Evidence status.
- Decision status.

Chain-of-custody must preserve chronological order.

Chain-of-custody must bind every artifact to the package identifier.

If chain-of-custody is missing, incomplete, conflicting, or not chronological:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Package Structure

The acquired evidence package must contain:

```text
governance/evidence/aws-object-lock/
├── object_lock_write_receipt.json
├── retention_configuration_evidence.json
├── legal_hold_evidence.json
├── export_verification_record.json
├── provider_audit_reference.md
├── AWS_LIVE_EVIDENCE_CHECKLIST.md
└── AWS_BLOCKER_003_EVALUATION.md
```

Optional future package artifacts must be added only when they are evidence-backed, redacted, hash-bound, and audit-referenced.

If required package files are missing or not evidence-backed:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Validation Checkpoints

Validation must check:

- Required artifacts are present.
- Required submission fields are present.
- Prohibited content is absent.
- Artifact hashes are present.
- Aggregate package hash is present.
- Hash continuity validates.
- S3 object version ID binds all provider evidence.
- Retention configuration binds to the object version.
- Legal hold evidence binds to the object version.
- Export verification binds to the USBAY WORM storage plan ID.
- Provider audit reference binds to each required event.
- Delete-denial evidence exists.
- Overwrite-denial evidence exists.

If any validation checkpoint fails:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Audit Checkpoints

Audit review must confirm:

- Evidence package manifest exists.
- Evidence artifact list is complete.
- Individual artifact hashes are recorded.
- Aggregate package hash is recorded.
- Chain-of-custody record is complete.
- Provider audit references are present.
- Reviewer decision record is present.
- Rejection record is present when applicable.
- Audit chronology is preserved.
- No audit record relies on human approval as evidence.

If any audit checkpoint fails:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Review Checkpoints

Reviewer must confirm:

- Evidence is complete.
- Evidence is redacted.
- Evidence is hash-bound.
- Evidence is audit-bound.
- Evidence is bound to the S3 object version ID.
- Evidence is bound to USBAY archive and WORM storage identifiers.
- Validation checkpoints passed.
- Audit checkpoints passed.
- No certification claim is made.
- BLOCKER-003 remains open until closure review is separately committed in GitHub.

Allowed review decisions:

- BLOCKED.
- READY_FOR_BLOCKER_003_REASSESSMENT.

`READY_FOR_BLOCKER_003_REASSESSMENT` does not close BLOCKER-003 and does not certify production readiness.

## Rejection Criteria

Reject the evidence package when:

- Any required provider artifact is missing.
- Any submission field is missing.
- Any prohibited content is present.
- Any hash is missing or mismatched.
- Any chain-of-custody record is missing, incomplete, conflicting, or not chronological.
- Any provider audit reference is missing.
- Any evidence artifact cannot be bound to the S3 object version ID.
- Retention evidence is missing or unverifiable.
- Legal hold evidence is missing or unverifiable.
- Export verification is missing or unverifiable.
- Delete-denial evidence is missing.
- Overwrite-denial evidence is missing.
- Human approval is offered as evidence.
- Provider marketing material is offered as evidence.
- Notion status text is offered as evidence.

Rejection outcome:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Retention Requirements

Acquired evidence must be retained with:

- Repository path or governed evidence package path.
- Retention class.
- Retention start timestamp.
- Retention-until timestamp if applicable.
- Legal hold status.
- Artifact hash list.
- Aggregate package hash.
- Chain-of-custody record.
- Reviewer decision record.

Evidence retention must preserve auditability, chronology, and hash continuity.

Evidence retention must not store provider credentials, secrets, raw payloads, approval contents, private keys, or raw regulator exports.

If retention requirements are missing or unverifiable:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Reassessment Boundary

This acquisition package prepares evidence intake only.

This package does not verify AWS.

This package does not certify immutable storage.

This package does not close BLOCKER-003.

Only evidence may support a future BLOCKER-003 reassessment.
