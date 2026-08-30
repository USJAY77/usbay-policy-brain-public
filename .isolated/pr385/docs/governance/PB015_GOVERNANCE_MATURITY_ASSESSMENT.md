# PB-015 Governance Maturity Assessment

PB-015 reconstructs the local governance maturity evidence required by PB-016.
It evaluates local PB-005 through PB-014 governance evidence and produces a
canonical maturity report, capability matrix, and governance scorecard.

PB-015 is local governance assessment only. It does not grant regulatory
certification, legal compliance certification, external certification, or
production readiness.

## Inputs

PB-015 reads local evidence from a governance evidence root containing PB-005
through PB-014 artifacts.

Required controls:

- PB-005 live evidence collection
- PB-006 evidence integrity
- PB-007 independent verification
- PB-008 timestamp/non-repudiation governance
- PB-009 immutable evidence archive
- PB-010 governance chain certification
- PB-011 governance drift detection
- PB-012 governance control registry
- PB-013 continuous governance monitor
- PB-014 governance recovery validation

## Outputs

PB-015 generates these files only when explicitly executed:

- `governance/evidence/pb015_maturity/pb015_maturity_report.json`
- `governance/evidence/pb015_maturity/pb015_capability_matrix.json`
- `governance/evidence/pb015_maturity/pb015_governance_scorecard.json`

## Schemas

- `usbay.pb015.governance_maturity_report.v1`
- `usbay.pb015.capability_matrix.v1`
- `usbay.pb015.governance_scorecard.v1`

## Required Common Fields

Every output includes:

- `schema`
- `actor`
- `device`
- `policy_version`
- `decision`
- `fail_closed`
- `generated_at`
- `errors`
- `local_governance_assessment_only`
- `no_external_certification_claim`
- `no_regulatory_certification_claim`
- `no_legal_compliance_certification_claim`
- `no_production_readiness_claim`
- `aws_access_performed`
- `postgresql_access_performed`
- `tsa_access_performed`
- `external_network_access_performed`
- `external_certification_provider_access_performed`

## Fail-Closed Conditions

PB-015 returns `Decision: BLOCKED` when:

- any required PB-005 through PB-014 evidence file is missing
- any required upstream schema is invalid
- any required upstream evidence decision is not `VERIFIED`
- any required upstream evidence has `fail_closed` other than `false`
- the PB-015 output directory contains unsupported artifacts
- the evidence root is missing

## Execution

Contract execution:

```bash
python3 scripts/pb015_governance_maturity_assessment.py \
  governance/evidence \
  governance/evidence/pb015_maturity
```

Evidence generation requires explicit human approval. Do not run this command
against tracked evidence as part of validation-only work.

## Downstream Dependencies

PB-016 consumes PB-015 directly. PB-017 consumes PB-016. PB-018 consumes PB-017
plus PB-010, PB-013, and PB-014. PB-019 explains PB-018. PB-020 validates
freshness and trust state across PB-016 through PB-019.

## Governance Rule

Evidence before claims. Missing, blocked, unverifiable, unsupported, or stale
governance evidence must keep the chain blocked until a human-approved
regeneration PB produces valid evidence.
