# WORM Archive Verification Framework

Purpose: define a WORM archive verification framework that proves whether exported evidence bundles, signatures, timestamps, audit lineage records, validation results, and review decisions remain immutable after archival.

Runtime impact: none.

AWS resource creation: none.

Credentials stored in repository: prohibited.

Private keys stored in repository: prohibited.

Certification claim: prohibited.

Blocker status change: prohibited.

Default decision: BLOCKED.

## Framework Files

WORM archive verification files:

- `governance/worm_archive/worm_archive_schema.json`
- `governance/worm_archive/worm_archive_example.json`
- `governance/worm_archive/worm_archive_relationships.md`
- `scripts/verify_worm_archive.py`

## Archive Manifest Validation

Archive manifest validation requires:

- Archive provider reference.
- Archive object ID.
- Archive object version ID.
- Archive manifest path.
- Archive manifest SHA256.
- Provider write receipt hash.
- Provider retention evidence hash.
- Provider legal hold evidence hash.
- Export verification hash.

If any required archive metadata is missing, verification blocks.

## Evidence Bundle Hash Verification

Evidence bundle verification compares:

- Expected evidence bundle SHA256.
- Archived evidence bundle SHA256.
- Current source artifact SHA256 when the source file exists locally.

Any mismatch blocks verification.

## Signature Hash Verification

Signature archive verification compares the expected and archived signature record hashes and requires a retained archive object reference.

Missing signature archive evidence blocks verification.

## Timestamp Hash Verification

Timestamp archive verification compares the expected and archived timestamp record hashes and requires archive retention metadata.

Missing timestamp archive evidence blocks verification.

## Audit Lineage Hash Verification

Audit lineage archive verification compares the expected and archived lineage hashes and requires continuity to the archive manifest.

Missing audit lineage archive evidence blocks verification.

## Review Decision Hash Verification

Review decision archive verification compares the expected and archived review decision hashes and requires linkage to validation results and the archive manifest.

Human approval is not archive evidence unless bound to signed, timestamped, hash-verified, retained archive records.

## Retention Metadata Validation

Retention validation requires:

- Retention mode.
- Retention until timestamp.
- Legal hold status.
- Provider retention evidence.
- Provider legal hold evidence.

Missing retention metadata produces:

```text
WORM_RETENTION_INCOMPLETE
```

## Immutability Status Validation

Immutability validation requires verified immutable status for the archive record and for every required archived artifact.

Missing or unverified immutability produces:

```text
WORM_IMMUTABILITY_UNVERIFIED
```

## Missing Archive And Hash Mismatch Detection

Missing archive detection emits:

```text
WORM_ARCHIVE_MISSING
```

Hash mismatch detection emits:

```text
WORM_HASH_MISMATCH
```

## Fail-Closed Verification

Run:

```text
python3 scripts/verify_worm_archive.py
```

Placeholder expected result:

```text
Decision = BLOCKED
WORM_ARCHIVE_MISSING
WORM_HASH_MISMATCH
WORM_RETENTION_INCOMPLETE
WORM_IMMUTABILITY_UNVERIFIED
```

Archive verification passes only when all required archive records, relationships, artifact hashes, provider receipts, retention metadata, legal hold evidence, export verification evidence, and immutability statuses exist and verify.

This framework does not create provider resources.

This framework does not create certification claims.

This framework does not change blocker status.
