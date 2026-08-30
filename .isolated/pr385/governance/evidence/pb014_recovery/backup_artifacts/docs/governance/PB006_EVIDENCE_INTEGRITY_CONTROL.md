# PB-006 Evidence Integrity Control

Purpose: bind governance evidence artifacts to SHA256 hashes and a signed evidence manifest before review, export, or WORM preservation.

Runtime impact: none.

Provider impact: none. This control does not call AWS, create WORM storage, close PB-006, or make regulator-grade retention claims.

## Control Behavior

The utility `scripts/pb006_evidence_integrity.py` supports two modes:

- `generate <evidence_dir>` creates `pb006_signed_evidence_manifest.json` and `pb006_integrity_report.json`.
- `verify <evidence_dir>` verifies the signed manifest and rewrites `pb006_integrity_report.json`.

Every evidence artifact in the directory is hashed with SHA256. The manifest records:

- artifact path
- artifact SHA256 hash
- aggregate hash
- deterministic manifest signature
- PB-005 compatibility flag
- explicit no-provider/no-WORM-closure claims

## Fail-Closed Rules

Decision: BLOCKED when:

- the signed manifest is missing
- any artifact listed in the manifest is missing
- any artifact hash changes
- any unmanifested artifact appears after signing
- the aggregate hash mismatches
- the manifest signature mismatches

Human approval cannot override a failed integrity check.

## PB-005 Compatibility

The control is compatible with PB-005 evidence artifacts, including:

- `pb005_endpoint_evidence.json`
- `pb005_schema_evidence.json`
- `pb005_write_receipt.json`
- `pb005_read_receipt.json`
- `pb005_persistence_evidence.json`
- `pb005_evidence_manifest.json`

The PB-006 integrity report does not prove external WORM retention. It proves local evidence artifact integrity before WORM/provider evidence is collected.

## Commands

Generate:

```bash
python3 scripts/pb006_evidence_integrity.py generate governance/evidence/pb005
```

Verify:

```bash
python3 scripts/pb006_evidence_integrity.py verify governance/evidence/pb005
```

Expected success:

```text
Decision: VERIFIED
PB006_EVIDENCE_INTEGRITY_VERIFIED
```

Expected fail-closed output:

```text
Decision: BLOCKED
```
