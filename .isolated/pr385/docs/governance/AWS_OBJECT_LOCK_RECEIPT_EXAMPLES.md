# AWS Object Lock Receipt Examples

Purpose: define redacted example receipt structures for the AWS S3 Object Lock pilot.

Runtime impact: none.

Production activation: prohibited.

Certification claim: prohibited.

Provider credentials in repository: prohibited.

Default decision: BLOCKED.

## Valid Receipt Shape

This is a redacted structure only. It is not provider evidence.

Required fields:

- provider_id: aws_s3_object_lock
- aws_account_boundary: redacted account boundary reference
- aws_region: redacted region reference
- s3_bucket_identifier: redacted bucket identifier
- s3_object_key: redacted object key
- s3_object_version_id: redacted object version ID
- object_lock_write_receipt: redacted provider write receipt
- object_lock_mode: governance retention mode reference
- retention_configuration_evidence: redacted retention configuration evidence
- retain_until_timestamp: redacted retain-until timestamp
- legal_hold_evidence: redacted legal hold evidence
- legal_hold_status: redacted legal hold status
- export_verification_evidence: redacted export verification evidence
- provider_audit_reference: redacted provider audit reference
- sha256_evidence_hash: 64-character SHA256 evidence hash
- usbay_sealed_archive_id: redacted USBAY sealed archive ID
- usbay_archive_root_hash: 64-character USBAY archive root hash
- usbay_worm_storage_plan_id: redacted USBAY WORM storage plan ID

Expected decision when all required fields are present and verified:

Decision: PILOT_VERIFIED.

This decision is pilot-only and does not certify production readiness.

## Missing Receipt Example

Missing:

- object_lock_write_receipt

Expected output:

Decision: BLOCKED.

Reason: Object Lock write receipt is missing.

## Missing Retention Evidence Example

Missing:

- retention_configuration_evidence
- retain_until_timestamp

Expected output:

Decision: BLOCKED.

Reason: Retention configuration evidence is missing.

## Missing Legal Hold Evidence Example

Missing:

- legal_hold_evidence
- legal_hold_status

Expected output:

Decision: BLOCKED.

Reason: Legal hold evidence is missing.

## Missing Export Verification Example

Missing:

- export_verification_evidence

Expected output:

Decision: BLOCKED.

Reason: Export verification evidence is missing.

## Missing Provider Audit Reference Example

Missing:

- provider_audit_reference

Expected output:

Decision: BLOCKED.

Reason: Provider audit reference is missing.

## Hash Mismatch Example

Condition:

- sha256_evidence_hash does not match usbay_archive_root_hash

Expected output:

Decision: BLOCKED.

Reason: SHA256 evidence hash does not match USBAY archive root hash.

## Forbidden Credential Example

Forbidden field present:

- aws_secret_access_key

Expected output:

Decision: BLOCKED.

Reason: Provider credentials must not be stored in repository evidence.

## BLOCKER-003 Boundary

Receipt examples do not close BLOCKER-003.

BLOCKER-003 remains OPEN until real Object Lock write receipt, retention configuration evidence, legal hold evidence, export verification evidence, and provider audit reference exist and validate.
