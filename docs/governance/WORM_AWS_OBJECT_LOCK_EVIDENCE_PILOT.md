# AWS Object Lock Evidence Pilot

Purpose: prepare a governed AWS S3 Object Lock evidence pilot without deploying infrastructure, configuring credentials, modifying runtime enforcement, or making certification claims.

Runtime impact: none.

Production activation: prohibited.

Certification claim: prohibited.

Regulator-grade assertion: prohibited.

Default decision: BLOCKED.

## Scope

This document defines the evidence USBAY must collect before an AWS Object Lock pilot can be considered verified.

This document does not prove AWS provider capability.

This document does not prove USBAY has configured AWS Object Lock.

This document does not close BLOCKER-003.

## Required AWS Evidence

The AWS pilot evidence package must include:

- AWS account boundary.
- AWS region.
- S3 bucket identifier.
- S3 object key.
- S3 object version ID.
- Object Lock mode.
- Retain-until timestamp.
- Legal hold status.
- Immutable write receipt.
- Provider audit event reference.
- Export verification record.
- SHA256 evidence hash.
- USBAY sealed archive ID.
- USBAY archive root hash.
- USBAY WORM storage plan ID.

If any required evidence is missing:

Decision: BLOCKED.

## Verification Requirements

The AWS pilot may be marked `PILOT_VERIFIED` only when:

- Provider write receipt exists.
- Provider object version ID exists.
- Retention evidence exists.
- Legal hold evidence exists.
- Immutable write evidence exists.
- Provider audit event reference exists.
- Export verification evidence exists.
- SHA256 evidence hash matches the USBAY archive root hash.
- Delete attempt is denied.
- Overwrite attempt is denied.
- Provider outage fails closed.
- Diagnostics remain hash-only and redacted.

## Failure Conditions

Decision: BLOCKED when:

- AWS account boundary is missing.
- AWS region is missing.
- S3 bucket identifier is missing.
- S3 object key is missing.
- S3 object version ID is missing.
- Object Lock mode is missing.
- Retain-until timestamp is missing.
- Legal hold status is missing.
- Immutable write receipt is missing.
- Provider audit event reference is missing.
- Export verification record is missing.
- SHA256 evidence hash is missing or mismatched.
- Delete attempt is allowed.
- Overwrite attempt is allowed.
- Provider outage prevents verification.
- Provider capability is not verified by evidence.
- Any credential, secret, raw payload, approval content, private key, or raw regulator export appears in evidence.

## Forbidden Evidence Content

The AWS pilot evidence package must not contain:

- AWS access key ID.
- AWS secret access key.
- AWS session token.
- Provider credentials.
- Private keys.
- Raw governance payloads.
- Approval contents.
- Raw regulator exports.

If forbidden evidence content is detected:

Decision: BLOCKED.

## Audit Record Requirements

The AWS pilot audit record must include:

- Pilot date.
- Pilot actor.
- Provider ID: `aws_s3_object_lock`.
- Evidence package hash.
- USBAY sealed archive ID.
- USBAY archive root hash.
- USBAY WORM storage plan ID.
- Provider object identifier.
- Provider object version identifier.
- Retention evidence reference.
- Legal hold evidence reference.
- Immutable write receipt reference.
- Provider audit event reference.
- Export verification record ID.
- Delete-denial test result.
- Overwrite-denial test result.
- Provider-outage fail-closed test result.
- Redaction verification result.

If any audit record requirement is missing:

Decision: BLOCKED.

## Certification Boundary

This AWS Object Lock evidence pilot is preparation only.

It does not certify production readiness.

It does not certify regulator-grade immutable storage.

It does not close BLOCKER-003 without real provider evidence, test evidence, audit evidence, and certification lifecycle review.
