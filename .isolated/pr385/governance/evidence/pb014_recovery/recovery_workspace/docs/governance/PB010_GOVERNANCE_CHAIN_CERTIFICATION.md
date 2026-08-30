# PB-010 Local Governance Chain Certification Control

## Purpose

PB-010 certifies the local USBAY governance evidence chain from PB-005 through PB-009.

The control verifies that each prior governance control has produced the required local evidence, that each report uses the expected schema, and that the chain remains locally verifiable.

## Scope

PB-010 validates:

- PB-005 evidence artifacts
- PB-006 integrity report
- PB-007 independent verification report
- PB-008 timestamp and non-repudiation report
- PB-009 archive, retention, and restore verification reports

PB-010 generates:

- `pb010_chain_certificate.json`
- `pb010_chain_verification_report.json`
- `pb010_governance_scorecard.json`

## Authority Boundary

PB-010 is local governance validation only.

PB-010 must not call:

- AWS
- PostgreSQL
- Timestamp Authority services
- External networks

PB-010 does not claim:

- external certification
- regulator certification
- WORM provider verification
- production readiness
- third-party attestation

## Fail-Closed Conditions

PB-010 returns `Decision: BLOCKED` if any of the following occur:

- required PB-005 artifact missing
- PB-006 integrity report missing or not verified
- PB-007 independent verification report missing or not verified
- PB-008 timestamp report missing or not verified
- PB-009 archive report missing or not verified
- unsupported artifact detected
- report schema invalid
- report contains errors
- report indicates fail-closed state
- archive artifact hash mismatch
- timestamp verification failure
- archive restore verification failure

Missing evidence is failed evidence.

## Execution

Generate local governance chain certificate:

```bash
python3 scripts/pb010_governance_chain_certifier.py \
  governance/evidence/pb005 \
  governance/evidence/pb009_archive \
  governance/evidence/pb010_chain
```

Expected verified output:

```text
Decision: VERIFIED
PB010_GOVERNANCE_CHAIN_VERIFIED
```

Expected blocked output:

```text
Decision: BLOCKED
PB010_REQUIRED_ARTIFACT_MISSING:<artifact>
```

## Outputs

`pb010_chain_certificate.json` records:

- certificate id
- evidence chain scope
- artifact hashes
- aggregate hash
- deterministic certificate signature
- local-only validation boundary

`pb010_chain_verification_report.json` records:

- decision
- fail-closed status
- errors by control
- missing artifact detection
- unsupported artifact detection
- schema validation state
- timestamp verification state
- archive verification state

`pb010_governance_scorecard.json` records:

- PB-005 status
- PB-006 status
- PB-007 status
- PB-008 status
- PB-009 status
- verified control count
- maximum control count

## Governance Rule

Evidence before claims.

PB-010 may certify local governance evidence-chain completeness only. It must not be used as proof of external certification, external provider validation, or regulator-grade storage.
