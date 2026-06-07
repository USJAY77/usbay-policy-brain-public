# PB-009 Immutable Evidence Archive Control

## Purpose

PB-009 creates a local immutable evidence archive layer for PB-005 through PB-008 governance artifacts.

The control copies source evidence into an archive directory, records artifact hashes in an archive manifest, applies retention metadata, and verifies that archived artifacts can be restored without hash drift.

## Scope

PB-009 archives:

- PB-005 endpoint evidence
- PB-005 schema evidence
- PB-005 write receipt
- PB-005 read receipt
- PB-005 persistence evidence
- PB-005 evidence manifest
- PB-005 final execution report
- PB-006 signed evidence manifest
- PB-006 integrity report
- PB-007 independent verification report
- PB-008 timestamp receipt
- PB-008 non-repudiation report

PB-009 generates:

- `pb009_archive_manifest.json`
- `pb009_retention_report.json`
- `pb009_restore_verification_report.json`
- `pb009_archive_integrity_report.json`

## Authority Boundary

PB-009 does not call:

- AWS
- PostgreSQL
- External WORM providers
- External timestamp authorities
- External networks

PB-009 does not claim:

- External WORM storage exists
- Regulator-grade immutability exists
- Certification readiness
- Provider verification

The control is local archive evidence only.

## Archive Layout

Default archive location:

```text
governance/evidence/pb009_archive/
├── artifacts/
│   ├── pb005_endpoint_evidence.json
│   ├── pb005_schema_evidence.json
│   ├── pb005_write_receipt.json
│   ├── pb005_read_receipt.json
│   ├── pb005_persistence_evidence.json
│   ├── pb005_evidence_manifest.json
│   ├── pb005_final_execution_report.json
│   ├── pb006_signed_evidence_manifest.json
│   ├── pb006_integrity_report.json
│   ├── pb007_verification_report.json
│   ├── pb008_timestamp_receipt.json
│   └── pb008_non_repudiation_report.json
├── pb009_archive_manifest.json
├── pb009_retention_report.json
├── pb009_restore_verification_report.json
└── pb009_archive_integrity_report.json
```

## Execution

Create archive:

```bash
python3 scripts/pb009_immutable_archive.py archive governance/evidence/pb005 governance/evidence/pb009_archive
```

Verify archive:

```bash
python3 scripts/pb009_immutable_archive.py verify governance/evidence/pb009_archive
```

Expected verified output:

```text
Decision: VERIFIED
PB009_ARCHIVE_VERIFICATION_VERIFIED
```

## Fail-Closed Conditions

PB-009 returns `Decision: BLOCKED` if any of the following occur:

- Required source artifact missing
- Archived artifact missing
- Archive manifest missing
- Archive manifest signature mismatch
- Archive artifact hash mismatch
- Aggregate hash mismatch
- Unsupported archive artifact present
- Retention metadata missing
- Retention period invalid
- Retention policy allows deletion or overwrite
- Restore verification fails

## Retention Rules

The local retention metadata requires:

- `delete_allowed: false`
- `overwrite_allowed: false`
- `legal_hold_required_before_delete: true`
- positive retention duration
- future `retention_until` timestamp

Any retention ambiguity is a governance failure.

## Governance Rule

Evidence before claims.

PB-009 may support local archive integrity and restore verification. It must not be used as proof of external WORM storage, external immutability, or certification closure.
