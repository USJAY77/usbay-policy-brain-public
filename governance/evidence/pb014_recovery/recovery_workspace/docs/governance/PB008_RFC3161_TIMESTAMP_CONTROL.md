# PB-008 RFC3161 Timestamp Governance Control

## Purpose

PB-008 adds timestamp evidence for signed USBAY evidence manifests.

The control binds the PB-006 signed evidence manifest to an RFC3161-compatible timestamp receipt and produces a non-repudiation report. The verifier is independent, local-first, and fail-closed.

## Scope

PB-008 validates:

- PB-006 signed evidence manifest presence
- PB-006 signed evidence manifest SHA256 hash
- Timestamp receipt presence
- Timestamped artifact reference
- Timestamp Authority response metadata
- Timestamp token hash
- Timestamp Authority signature hash
- Non-repudiation report status

PB-008 generates:

- `pb008_timestamp_receipt.json`
- `pb008_non_repudiation_report.json`

## Authority Boundary

The PB-008 utility must not call:

- AWS
- PostgreSQL
- External Timestamp Authorities
- External networks

The receipt uses deterministic RFC3161-compatible metadata so the timestamp control can be tested and independently verified without credentials, private keys, or provider access.

PB-008 does not claim:

- External TSA verification
- Regulator-grade timestamping
- Certification readiness
- WORM closure

## Fail-Closed Conditions

PB-008 returns `Decision: BLOCKED` if any of the following occur:

- Timestamp receipt missing
- Timestamp Authority response missing
- Timestamp Authority response invalid
- Timestamp Authority signature invalid
- Timestamped manifest missing
- Timestamped manifest hash mismatch
- Timestamp message imprint mismatch
- Unsupported timestamped artifact
- Timestamp metadata missing

Unknown state is unsafe state. Missing timestamp evidence is blocked evidence.

## Execution

Generate timestamp receipt and report:

```bash
python3 scripts/pb008_timestamp_verifier.py generate governance/evidence/pb005
```

Verify existing timestamp receipt:

```bash
python3 scripts/pb008_timestamp_verifier.py verify governance/evidence/pb005
```

Expected verified output:

```text
Decision: VERIFIED
PB008_TIMESTAMP_VERIFICATION_VERIFIED
```

Expected blocked output:

```text
Decision: BLOCKED
PB008_TIMESTAMP_MISSING
```

## Report Fields

`pb008_non_repudiation_report.json` records:

- `decision`
- `fail_closed`
- `errors`
- `receipt_path`
- `timestamp_receipt_present`
- `timestamp_valid`
- `manifest_hash_verified`
- `tsa_response_verified`
- `aws_access_performed`
- `postgresql_access_performed`
- `no_certification_claim`

## Governance Rule

Evidence before claims.

If timestamp evidence is missing, invalid, mismatched, unsupported, or unverifiable, PB-008 must block and produce a fail-closed report.
