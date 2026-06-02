# WORM Archive Relationships

Purpose: define verification relationships between archived evidence bundles, signatures, timestamps, audit lineage records, validation results, and review decisions.

Runtime impact: none.

AWS resource creation: none.

Credentials and private keys in repository: prohibited.

Certification claim: prohibited.

Default decision: BLOCKED.

## Required Archive Verification Chain

The WORM archive verification chain must link:

1. Evidence bundle archive record to signature record archive evidence.
2. Signature record archive evidence to timestamp record archive evidence.
3. Timestamp record archive evidence to audit lineage archive evidence.
4. Validation result archive evidence to review decision archive evidence.
5. Review decision archive evidence to the archive manifest.

If any archive record is missing:

Decision = BLOCKED

Failure code: WORM_ARCHIVE_MISSING

If any expected hash differs from the archived hash or the current repository artifact hash:

Decision = BLOCKED

Failure code: WORM_HASH_MISMATCH

If retention mode, retention expiry, legal hold state, provider write receipt, retention evidence, legal hold evidence, or export verification evidence is missing:

Decision = BLOCKED

Failure code: WORM_RETENTION_INCOMPLETE

If the archive provider does not supply verified immutability status for every required artifact:

Decision = BLOCKED

Failure code: WORM_IMMUTABILITY_UNVERIFIED

## Required Archived Artifacts

The archive verification package must cover:

- Evidence bundle.
- Signature record.
- Timestamp record.
- Audit lineage record.
- Validation result.
- Review decision.

## Archive Manifest Validation

Archive manifest validation requires:

- Archive record ID.
- Provider reference.
- Archive object ID.
- Archive object version ID.
- Archive manifest path.
- Archive manifest SHA256.
- Retention mode.
- Retention until timestamp.
- Legal hold status.
- Immutability status.
- Provider write receipt hash.
- Provider retention evidence hash.
- Provider legal hold evidence hash.
- Export verification hash.

## Hash Verification

Hash verification must compare:

- Expected artifact SHA256.
- Archived artifact SHA256.
- Current repository artifact SHA256 when the source artifact exists locally.

Any mismatch blocks verification.

## Retention Metadata Validation

Retention metadata validation requires:

- Explicit retention mode.
- Explicit retention expiry.
- Explicit legal hold state.
- Provider retention evidence.
- Provider legal hold evidence.

Human statements are not retention evidence.

## Immutability Status Validation

Immutability status validation requires provider-backed evidence that the archived object cannot be overwritten or deleted before the governed retention period expires.

No provider-backed immutability evidence means:

Decision = BLOCKED

WORM_IMMUTABILITY_UNVERIFIED

## Fail-Closed Verification

Archive verification must fail closed when:

- Required archive record is missing.
- Required artifact is missing.
- Required hash is missing.
- Hashes do not match.
- Retention metadata is missing.
- Legal hold status is missing.
- Immutability status is missing or unverified.
- Required chain relationship is missing.

Fail-closed output:

Decision = BLOCKED

WORM_ARCHIVE_MISSING

WORM_HASH_MISMATCH

WORM_RETENTION_INCOMPLETE

WORM_IMMUTABILITY_UNVERIFIED

## Governance Boundary

This framework does not create AWS resources, store credentials, store private keys, change runtime behavior, change blocker status, or make certification claims.

BLOCKER-003 remains OPEN until real external immutable archive evidence is present, hash-verified, retention-verified, immutability-verified, independently reviewed, and recorded through the governed certification process.
