# PB-020 Governance Evidence Freshness Validation

PB-020 validates local governance evidence freshness before governance
decisions are trusted. It detects stale evidence, stale certification results,
stale maturity reports, stale action trackers, timestamp defects, and schema
version drift.

PB-020 does not grant regulatory certification, legal certification, external
certification, or production readiness.

## Inputs

PB-020 reads local artifacts from:

- PB-016 governance improvement planning
- PB-017 governance action tracking
- PB-018 agent governance certification
- PB-019 certification explanation

## Outputs

PB-020 generates:

- `pb020_freshness_report.json`
- `pb020_staleness_report.json`
- `pb020_version_alignment_report.json`
- `pb020_evidence_freshness_scorecard.json`

## Freshness Rules

Every governed artifact must contain:

- `schema`
- `generated_at`
- current expected governance schema version
- timestamp within the configured maximum age window

By default, PB-020 treats artifacts older than 168 hours as stale.

## Fail-Closed Conditions

PB-020 returns `Decision: BLOCKED` when:

- governance evidence is missing
- governance evidence has an invalid timestamp
- governance evidence is stale
- certification results are stale
- maturity reports are stale
- action trackers are stale
- governance schema versions do not match expected versions
- unsupported governance artifacts are present
- PB-016 maturity planning evidence is not trusted
- PB-017 action tracking evidence is not trusted
- PB-018 certification evidence is not trusted

## Execution

```bash
python3 scripts/pb020_evidence_freshness_validation.py \
  governance/evidence/pb016_improvement \
  governance/evidence/pb017_action_tracking \
  governance/evidence/pb018_agent_governance \
  governance/evidence/pb019_certification_explanation \
  governance/evidence
```

## External Access Prohibition

PB-020 must not call:

- AWS
- PostgreSQL
- timestamp authorities
- external networks
- external certification providers

All outputs must explicitly record that no external certification, regulatory
certification, legal certification, or production readiness claim is made.
