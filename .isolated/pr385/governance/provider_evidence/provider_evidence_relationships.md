# Provider Evidence Relationships

Purpose: define how real provider-submitted evidence packages are validated against evidence, signing, timestamp, audit lineage, review, export, and WORM archive controls.

Runtime impact: none.

AWS resource creation: none.

Credentials and private keys in repository: prohibited.

Certification claim: prohibited.

Default decision: BLOCKED.

## Required Intake Chain

The provider evidence intake chain must link:

1. Provider evidence package to validation result.
2. Validation result to signature record.
3. Signature record to timestamp record.
4. Timestamp record to audit lineage.
5. Audit lineage to review decision.
6. Review decision to export bundle.
7. Export bundle to WORM archive verification.

If provider evidence is missing:

Decision = BLOCKED

Failure code: PROVIDER_EVIDENCE_MISSING

If provider evidence is malformed, hash-invalid, path-invalid, missing chain of custody, missing control linkage, or contains unsupported state:

Decision = BLOCKED

Failure code: PROVIDER_EVIDENCE_INVALID

If provider evidence is present but not independently verified across signing, timestamp, lineage, review, export, and WORM controls:

Decision = BLOCKED

Failure code: PROVIDER_EVIDENCE_UNVERIFIED

## Required Provider Artifacts

The intake package must include:

- Provider write receipt.
- Retention configuration evidence.
- Legal hold evidence.
- Export verification record.
- Provider audit reference.
- Chain of custody.
- Evidence manifest.

## Evidence Intake Validation

Evidence intake validation requires:

- Provider name.
- Provider submission reference.
- Submission timestamp.
- Chain-of-custody reference.
- Evidence manifest path.
- Evidence manifest SHA256.
- Provider receipt SHA256.
- Review decision reference.
- Export bundle reference.
- WORM archive reference.

Missing provider submission metadata blocks intake.

## Signature Validation Linkage

Each provider artifact must reference a signature validation record.

Missing signature linkage blocks intake.

## Timestamp Validation Linkage

Each provider artifact must reference a timestamp validation record.

Missing timestamp linkage blocks intake.

## Audit Lineage Linkage

Each provider artifact must reference audit lineage evidence.

Missing audit lineage linkage blocks intake.

## Review Linkage

Each provider artifact must reference a review decision.

Human approval is not evidence unless signed, timestamped, lineage-linked, exported, and WORM-archived.

## Export Linkage

Each provider artifact must reference an export bundle.

Missing export linkage blocks intake.

## WORM Linkage

Each provider artifact must reference WORM archive verification evidence.

Missing WORM linkage blocks intake.

## Fail-Closed Verification

Provider evidence verification must fail closed when:

- Required provider artifact is missing.
- Required metadata is missing.
- Required artifact hash is missing or invalid.
- Required control linkage is missing.
- Required relationship is missing.
- Verification status is not VERIFIED.

Fail-closed output:

Decision = BLOCKED

PROVIDER_EVIDENCE_MISSING

PROVIDER_EVIDENCE_INVALID

PROVIDER_EVIDENCE_UNVERIFIED

## Governance Boundary

This framework does not create AWS resources, store credentials, store private keys, change runtime behavior, change blocker status, or make certification claims.

BLOCKER-003 remains OPEN until real provider evidence is submitted, hash-verified, signed, timestamped, lineage-linked, reviewed, exported, WORM-verified, and recorded through the governed certification process.
