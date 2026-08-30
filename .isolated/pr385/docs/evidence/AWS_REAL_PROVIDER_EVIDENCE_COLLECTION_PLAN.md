# AWS Real Provider Evidence Collection Plan

Purpose: prepare the operational process required to request, receive, validate, review, and archive real AWS S3 Object Lock provider evidence for BLOCKER-003 evaluation.

Runtime impact: none.

Gateway impact: none.

Policy enforcement impact: none.

AWS resource creation: prohibited by this plan.

Provider credentials stored in repository: prohibited.

Certification claim: prohibited.

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Request Workflow

The evidence request must be issued from the governed AWS provider evidence request package.

Required request inputs:

- Evidence request owner.
- Provider contact owner.
- Requested evidence artifact list.
- Required evidence naming conventions.
- Required redaction rules.
- Required delivery format.
- Required chain-of-custody metadata.
- Required hash and audit reference fields.

Required requested artifacts:

- Object Lock write receipt.
- Retention configuration evidence.
- Legal hold evidence.
- Export verification record.
- Provider audit reference.
- Chain-of-custody record.
- Evidence manifest.

If the request omits any required artifact:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Provider Contact Workflow

Provider contact must be controlled and auditable.

Provider contact record must include:

- Contact actor.
- Contact timestamp.
- Provider contact channel.
- Evidence request package version.
- Scope of requested evidence.
- Statement that credentials must not be submitted.
- Statement that certification claims must not be submitted.
- Statement that provider verification is not assumed.
- Follow-up deadline.

Provider contact must not request or receive:

- AWS access key ID.
- AWS secret access key.
- AWS session token.
- Provider credentials.
- Private keys.
- Raw governance payloads.
- Approval contents.
- Raw regulator exports.

If provider contact produces credentials or prohibited content:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Receipt Workflow

Evidence receipt must record:

- Receipt actor.
- Receipt timestamp.
- Provider identifier.
- Package identifier.
- Received artifact list.
- Missing artifact list.
- Redaction status.
- Initial prohibited-content scan result.
- Initial hash manifest status.
- Storage path.

Receipt must fail closed when:

- Required artifacts are missing.
- Artifact names are ambiguous.
- Prohibited content is present.
- Hash manifest is missing.
- Chain-of-custody metadata is missing.

Receipt failure outcome:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Validation Workflow

Validation must execute after receipt and before review.

Validation must confirm:

- Required files exist.
- Evidence manifest exists.
- Chain of custody exists.
- Object Lock write receipt exists.
- Retention configuration evidence exists.
- Legal hold evidence exists.
- Export verification record exists.
- Provider audit reference exists.
- S3 object version ID binds required evidence.
- SHA256 hashes exist.
- SHA256 hash continuity is valid.
- Prohibited content is absent.
- Placeholder values are absent.

Validation command:

```text
python3 scripts/validate_provider_evidence.py governance/evidence/aws-object-lock/provider-submissions
```

If validation fails:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Review Workflow

Review begins only after validation completes.

Reviewer must verify:

- Evidence completeness.
- Hash continuity.
- Chain-of-custody chronology.
- Provider audit references.
- Object version binding.
- Retention evidence.
- Legal hold evidence.
- Export verification evidence.
- Absence of credentials and prohibited content.
- Validation result.

Allowed review outcomes:

- BLOCKED.
- READY_FOR_BLOCKER_003_REASSESSMENT.

`READY_FOR_BLOCKER_003_REASSESSMENT` does not close BLOCKER-003 and does not create a certification claim.

## Rejection Workflow

Reject the evidence package when:

- Any required artifact is missing.
- Any required hash is missing or mismatched.
- Chain-of-custody metadata is incomplete.
- Provider audit reference is missing.
- Evidence cannot be bound to the S3 object version ID.
- Evidence cannot be bound to USBAY archive or WORM storage identifiers.
- Prohibited content is present.
- Placeholder evidence remains.
- Human approval is offered as evidence.
- Provider marketing material is offered as evidence.

Rejection record must include:

- Rejection actor.
- Rejection timestamp.
- Rejection reason.
- Missing or failed evidence item.
- Required remediation.
- Decision status.

Rejection outcome:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Evidence Archive Workflow

Accepted evidence for review must be archived in the governed evidence package path.

Archive record must include:

- Evidence package path.
- Artifact list.
- Artifact hashes.
- Aggregate package hash.
- Retention class.
- Retention start timestamp.
- Legal hold status.
- Chain-of-custody record.
- Reviewer decision.
- Validation output.

The archive must not contain credentials, secrets, raw payloads, approval contents, private keys, or raw regulator exports.

If archive metadata is missing or prohibited content is present:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Escalation Workflow

Escalate when:

- Provider evidence is unavailable.
- Provider evidence is incomplete.
- Provider evidence contains prohibited content.
- Provider audit references are missing.
- Hash continuity fails.
- Chain-of-custody metadata is incomplete.
- Reviewer and validator disagree.
- GitHub and external status summaries disagree.

Escalation record must include:

- Escalation actor.
- Escalation timestamp.
- Escalation reason.
- Evidence item affected.
- Current blocker status.
- Current certification status.
- Required next action.

Escalation outcome:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Chain-Of-Custody Responsibilities

Evidence request owner:

- Issues the evidence request.
- Records request metadata.
- Confirms no credentials are requested.

Provider contact owner:

- Controls provider communication.
- Records contact metadata.
- Rejects prohibited content.

Evidence receipt owner:

- Records received artifacts.
- Records missing artifacts.
- Performs initial prohibited-content scan.

Validation owner:

- Runs validation tooling.
- Records validation output.
- Blocks incomplete evidence.

Reviewer:

- Reviews evidence after validation.
- Records review decision.
- Does not substitute approval for evidence.

Archive owner:

- Archives redacted evidence.
- Records hashes, retention, legal hold, and chain-of-custody metadata.

## Reviewer Responsibilities

Reviewer must:

- Confirm validation output.
- Confirm required artifacts exist.
- Confirm evidence is redacted.
- Confirm hash continuity.
- Confirm chain-of-custody chronology.
- Confirm provider audit references.
- Confirm retention and legal hold evidence.
- Confirm export verification evidence.
- Confirm rejection criteria are absent.
- Record review outcome.

Reviewer must not:

- Close BLOCKER-003 without evidence.
- Create certification claims.
- Accept provider marketing material as evidence.
- Accept human approval as evidence.
- Accept Notion status as evidence.

## Approval Authority Matrix

| Authority | May Request Evidence | May Receive Evidence | May Validate Evidence | May Review Evidence | May Close BLOCKER-003 | May Certify |
|---|---|---|---|---|---|---|
| Evidence request owner | Yes | No | No | No | No | No |
| Provider contact owner | Yes | No | No | No | No | No |
| Evidence receipt owner | No | Yes | No | No | No | No |
| Validation owner | No | No | Yes | No | No | No |
| Reviewer | No | No | No | Yes | No | No |
| Archive owner | No | No | No | No | No | No |
| GitHub closure review | No | No | No | Yes | Only with complete evidence | No |
| Certification authority | No | No | No | Yes | No | Only after all certification controls pass |

No role may close BLOCKER-003 without complete evidence.

No role may certify from this plan.

## Final Decision Rule

If real AWS provider evidence is missing:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

If any workflow step fails:

BLOCKER-003 = OPEN.

Certification = BLOCKED.

Only complete, validated, reviewed, archived, audit-bound evidence may support a future BLOCKER-003 reassessment.
