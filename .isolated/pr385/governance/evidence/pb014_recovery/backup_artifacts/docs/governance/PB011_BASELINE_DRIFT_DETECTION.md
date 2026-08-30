# PB-011 Local Governance Baseline Drift Detection

## Purpose

PB-011 detects drift from the PB-010 certified local governance baseline.

The control creates a frozen baseline snapshot of PB-005 through PB-010 artifacts and then verifies that the current local governance evidence chain still matches that baseline.

## Scope

PB-011 validates:

- PB-005 evidence artifacts
- PB-006 integrity artifacts
- PB-007 independent verification report
- PB-008 timestamp and non-repudiation artifacts
- PB-009 archive, retention, restore, and integrity artifacts
- PB-010 chain certificate, verification report, and scorecard

PB-011 generates:

- `pb011_baseline_manifest.json`
- `pb011_drift_report.json`
- `pb011_drift_scorecard.json`

## Authority Boundary

PB-011 is local governance validation only.

PB-011 must not call:

- AWS
- PostgreSQL
- Timestamp Authority services
- External networks

PB-011 does not claim:

- external certification
- WORM certification
- regulator certification
- production readiness
- third-party attestation

## Execution

Create baseline:

```bash
python3 scripts/pb011_baseline_drift_detector.py baseline \
  governance/evidence/pb005 \
  governance/evidence/pb009_archive \
  governance/evidence/pb010_chain \
  governance/evidence/pb011_baseline
```

Verify drift:

```bash
python3 scripts/pb011_baseline_drift_detector.py verify \
  governance/evidence/pb005 \
  governance/evidence/pb009_archive \
  governance/evidence/pb010_chain \
  governance/evidence/pb011_baseline
```

Expected verified output:

```text
Decision: VERIFIED
PB011_BASELINE_DRIFT_VERIFICATION_VERIFIED
```

## Fail-Closed Conditions

PB-011 returns `Decision: BLOCKED` if any of the following occur:

- certified artifact missing
- artifact hash changed
- PB-010 certification artifact changed
- unsupported artifact detected
- baseline manifest missing
- baseline manifest signature mismatch
- baseline aggregate hash mismatch
- PB-010 governance score decreases
- baseline score unavailable

## Baseline Manifest

`pb011_baseline_manifest.json` records:

- baseline id
- tracked control list
- artifact hashes
- aggregate hash
- PB-010 certificate id
- PB-010 governance score
- deterministic baseline signature
- local-only validation boundary

## Drift Report

`pb011_drift_report.json` records:

- decision
- fail-closed status
- changed artifacts
- missing artifacts
- unsupported artifacts
- certification report drift
- baseline mismatch
- governance score decrease

## Drift Scorecard

`pb011_drift_scorecard.json` records:

- baseline artifact count
- current artifact count
- changed artifact count
- missing artifact count
- unsupported artifact count
- drift score
- maximum score

## Governance Rule

Evidence before claims.

Any drift from a certified local baseline is blocked until reviewed, explained, and re-baselined through governed evidence generation.
