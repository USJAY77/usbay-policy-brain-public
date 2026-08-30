# PB-016 Governance Improvement Planning

## Purpose

PB-016 generates a governance improvement roadmap from PB-015 maturity assessment results.

The control reads the PB-015 maturity report, capability matrix, and governance scorecard. It then produces an improvement plan, priority matrix, roadmap, and action register.

## Scope

PB-016 evaluates:

- control coverage
- governance maturity score
- capability gaps
- governance weaknesses
- improvement priorities
- recovery readiness
- monitoring readiness

PB-016 generates:

- `pb016_governance_improvement_plan.json`
- `pb016_governance_priority_matrix.json`
- `pb016_governance_roadmap.json`
- `pb016_governance_action_register.json`

## Authority Boundary

PB-016 is local governance planning only.

PB-016 must not call:

- AWS
- PostgreSQL
- Timestamp Authority services
- External networks
- External certification providers

PB-016 does not claim:

- regulatory certification
- external certification
- legal compliance certification
- production readiness

## Required Inputs

PB-016 requires:

- `pb015_maturity_report.json`
- `pb015_capability_matrix.json`
- `pb015_governance_scorecard.json`

Missing PB-015 evidence is a fail-closed planning condition.

## Fail-Closed Conditions

PB-016 returns `Decision: BLOCKED` when:

- maturity report missing
- capability matrix missing
- governance scorecard missing
- governance controls missing
- unsupported governance artifacts detected
- maturity score invalid
- governance score invalid
- PB-015 input report is not verified

## Execution

Run improvement planning:

```bash
python3 scripts/pb016_governance_improvement_planning.py \
  governance/evidence/pb015_maturity \
  governance/evidence/pb016_improvement
```

Expected verified output:

```text
Decision: VERIFIED
PB016_GOVERNANCE_IMPROVEMENT_PLAN_GENERATED
```

Expected blocked output when PB-015 evidence is missing:

```text
Decision: BLOCKED
PB016_MATURITY_REPORT_MISSING
PB016_CAPABILITY_MATRIX_MISSING
PB016_GOVERNANCE_SCORECARD_MISSING
```

## Governance Rule

Evidence before claims.

PB-016 may plan governance improvements only from PB-015 evidence. Missing or invalid maturity evidence blocks planning outputs from being treated as verified.
