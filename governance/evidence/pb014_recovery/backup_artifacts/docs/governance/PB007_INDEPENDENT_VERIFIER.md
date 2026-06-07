# PB-007 Independent Verifier

Purpose: independently verify a local evidence bundle without contacting AWS, PostgreSQL, or any external provider.

Runtime impact: none.

Network impact: none.

Provider impact: none.

## Verification Scope

`scripts/pb007_independent_verifier.py` validates:

- PB-005 evidence bundle
- PB-005 evidence manifest and artifact hashes
- PB-006 signed evidence manifest
- PB-006 integrity report

The verifier does not create evidence, connect to databases, call AWS APIs, or make production/WORM certification claims.

## Fail-Closed Conditions

Decision: BLOCKED when:

- any required PB-005 artifact is missing
- any PB-005 manifest hash mismatches
- PB-005 aggregate manifest hash mismatches
- any PB-005 artifact is not verified
- PB-006 signed manifest is missing
- PB-006 signature mismatches
- PB-006 artifact hash mismatches
- PB-006 integrity report is not verified
- unsupported artifacts are present in the bundle

Human approval cannot override verifier failure.

## Command

```bash
python3 scripts/pb007_independent_verifier.py governance/evidence/pb005
```

Expected success:

```text
Decision: VERIFIED
PB007_INDEPENDENT_VERIFICATION_VERIFIED
```

Expected fail-closed output:

```text
Decision: BLOCKED
```

## Report

The verifier writes:

```text
pb007_verification_report.json
```

The report records:

- final decision
- fail-closed state
- missing artifact detection
- artifact modification detection
- unsupported artifact detection
- explicit `aws_access_performed: false`
- explicit `postgresql_access_performed: false`
