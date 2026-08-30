# AWS BLOCKER-003 Closure Criteria

Purpose: define the exact evidence and review criteria required before BLOCKER-003 may transition from OPEN to CLOSED.

Runtime impact: none.

Gateway impact: none.

Policy enforcement impact: none.

AWS resource creation: prohibited by this criteria document.

Provider credentials stored in repository: prohibited.

Certification claim: prohibited.

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Mandatory Evidence List

BLOCKER-003 may be evaluated for closure only when all mandatory evidence exists:

- Object Lock write receipt.
- Retention configuration evidence.
- Legal hold evidence.
- Export verification record.
- Provider audit reference.
- S3 object version ID.
- SHA256 evidence hash.
- USBAY archive root hash.
- USBAY WORM storage plan ID.
- Delete-denial evidence during retention.
- Overwrite-denial evidence during retention.
- Chain-of-custody record.
- Evidence package manifest.
- Reviewer decision record.

If any mandatory evidence is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Validation Rules

Evidence validation must confirm:

- Object Lock write receipt exists and is bound to the S3 object version ID.
- Retention configuration evidence exists and is bound to the S3 object version ID.
- Legal hold evidence exists and is bound to the S3 object version ID.
- Export verification record exists and is bound to the USBAY WORM storage plan ID.
- Provider audit reference exists for write, retention, legal hold, delete-denial, overwrite-denial, and export verification events.
- SHA256 evidence hash matches the USBAY archive root hash.
- Evidence artifacts are redacted before repository storage.
- Evidence artifacts do not contain credentials, secrets, private keys, raw payloads, approval contents, or raw regulator exports.
- Evidence package manifest includes each required artifact.
- Chain-of-custody metadata is complete.

If any validation rule fails:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Reviewer Requirements

The reviewer must verify:

- All mandatory evidence exists.
- All evidence validation rules passed.
- Evidence hashes are present and match.
- Provider audit references are present.
- Chain-of-custody metadata is complete.
- No prohibited content exists in the evidence package.
- No human approval is being used as a substitute for provider evidence.
- No provider marketing material is being used as evidence.
- No screenshot without audit binding is being used as evidence.

Reviewer authority is limited to evidence review.

Reviewer approval alone cannot close BLOCKER-003.

## Approval Workflow

The approval workflow must proceed in this order:

1. Evidence package is assembled.
2. Evidence package manifest is generated.
3. Evidence artifact hashes are calculated.
4. Chain-of-custody metadata is recorded.
5. Evidence validation is executed.
6. Reviewer checks validation results.
7. Reviewer records decision.
8. BLOCKER-003 closure may be proposed only if all evidence and validation requirements pass.
9. Closure proposal must be committed in GitHub.
10. Certification status remains BLOCKED unless every required certification control is separately satisfied.

Allowed reviewer decisions:

- BLOCKED.
- READY_FOR_CLOSURE_REVIEW.

`READY_FOR_CLOSURE_REVIEW` is not a certification claim and does not close BLOCKER-003.

## Rejection Criteria

Reject BLOCKER-003 closure when:

- Any mandatory evidence is missing.
- Any evidence validation rule fails.
- Any evidence hash is missing or mismatched.
- Any provider audit reference is missing.
- Chain-of-custody metadata is incomplete.
- Evidence cannot be bound to the S3 object version ID.
- Evidence cannot be bound to the USBAY archive root hash.
- Evidence cannot be bound to the USBAY WORM storage plan ID.
- Delete-denial evidence is missing.
- Overwrite-denial evidence is missing.
- Provider credentials or secrets are present.
- Raw governance payloads are present.
- Approval contents are present.
- Raw regulator exports are present.
- Human approval is offered instead of provider evidence.
- Provider marketing material is offered instead of provider evidence.
- Notion status text is offered instead of GitHub evidence.

Rejection outcome:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Fail-Closed Decision Logic

If required evidence is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

If evidence is incomplete, unverifiable, unredacted, hash-mismatched, unaudited, or missing chain-of-custody metadata:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

If reviewer approval exists but evidence is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

If any source conflicts:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

Only evidence may support a future BLOCKER-003 closure.

## Required Audit Artifacts

The closure review package must include:

- Evidence package manifest.
- Object Lock write receipt artifact.
- Retention configuration evidence artifact.
- Legal hold evidence artifact.
- Export verification record artifact.
- Provider audit reference artifact.
- S3 object version ID binding record.
- SHA256 hash record for each artifact.
- Aggregate package hash.
- Chain-of-custody record.
- Validation result record.
- Reviewer decision record.
- Rejection record, if applicable.

If any audit artifact is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Closure Decision Matrix

| Condition | BLOCKER-003 Status | Certification Status | Decision |
|---|---|---|---|
| Any mandatory evidence missing | OPEN | BLOCKED | BLOCKED |
| Evidence present but hash mismatch exists | OPEN | BLOCKED | BLOCKED |
| Evidence present but provider audit reference missing | OPEN | BLOCKED | BLOCKED |
| Evidence present but chain of custody incomplete | OPEN | BLOCKED | BLOCKED |
| Evidence present but prohibited content detected | OPEN | BLOCKED | BLOCKED |
| Evidence present but reviewer approval missing | OPEN | BLOCKED | BLOCKED |
| Reviewer approval present but evidence incomplete | OPEN | BLOCKED | BLOCKED |
| All mandatory evidence present, validation passed, audit artifacts complete, reviewer decision recorded | READY_FOR_CLOSURE_REVIEW | BLOCKED | Not closed until GitHub closure review is committed |

This criteria document does not close BLOCKER-003.

This criteria document does not create a certification claim.
