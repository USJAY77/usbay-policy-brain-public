# RFC3161 Timestamp Relationships

Purpose: define timestamp relationships across evidence packages, validation results, review decisions, export bundles, and audit lineage records.

Runtime impact: none.

Certification claim: prohibited.

Default decision: BLOCKED.

## Required Timestamp Chain

The trusted timestamp chain must link:

1. Evidence package timestamp to validation result timestamp.
2. Validation result timestamp to review decision timestamp.
3. Review decision timestamp to export bundle timestamp.
4. Export bundle timestamp to audit lineage timestamp.

If any timestamp is missing:

Decision = BLOCKED

Failure code: TIMESTAMP_MISSING

If any timestamp is malformed, hash-mismatched, or lacks RFC3161-compatible token metadata:

Decision = BLOCKED

Failure code: TIMESTAMP_INVALID

If any timestamp chain link is missing or inconsistent:

Decision = BLOCKED

Failure code: TIMESTAMP_CHAIN_INCOMPLETE

## Evidence Timestamp Linkage

Evidence package timestamp records must include:

- Evidence package path.
- Evidence package SHA256 hash.
- RFC3161 token hash.
- TSA policy identifier.
- TSA certificate hash.
- Timestamp UTC value.

## Review Timestamp Linkage

Review decision timestamp records must include:

- Review decision path.
- Review decision SHA256 hash.
- Reviewer reference.
- RFC3161 token hash.
- Timestamp UTC value.

Reviewer approval is not evidence unless bound to timestamped evidence.

## Export Timestamp Linkage

Export bundle timestamp records must include:

- Export bundle path.
- Export bundle SHA256 hash.
- Bundle verification result.
- RFC3161 token hash.
- Timestamp UTC value.

## Audit Lineage Timestamp Linkage

Audit lineage timestamp records must include:

- Lineage record path.
- Lineage record SHA256 hash.
- Previous timestamp record hash.
- Current timestamp record hash.
- RFC3161 token hash.

## Fail-Closed Verification

Timestamp verification must fail closed when:

- Required timestamp record is missing.
- Timestamp subject path is missing.
- Timestamp subject hash is missing.
- RFC3161 token hash is missing.
- TSA policy identifier is missing.
- TSA certificate hash is missing.
- Timestamp UTC value is missing or invalid.
- Previous/current timestamp record hash continuity is incomplete.

Fail-closed output:

Decision = BLOCKED

TIMESTAMP_MISSING

TIMESTAMP_INVALID

TIMESTAMP_CHAIN_INCOMPLETE

## Governance Boundary

This framework does not create AWS resources, store credentials, change runtime behavior, change blocker status, or make certification claims.

BLOCKER-003 remains OPEN until real provider timestamp evidence is present, independently validated, and reviewed through the governed certification process.
