# PB-019 Certification Explanation

PB-019 explains why PB-018 agent governance certification returned
`BLOCKED`. It identifies the blocked governance areas, the underlying evidence
gaps, and the required actions before PB-018 may be re-evaluated.

PB-019 does not grant certification. It is an explanation and action-tracking
artifact only.

## Inputs

PB-019 reads the PB-018 local artifacts:

- `pb018_agent_governance_certificate.json`
- `pb018_agent_risk_assessment.json`
- `pb018_agent_scorecard.json`
- `pb018_agent_attestation.json`

## Outputs

PB-019 generates:

- `pb019_certification_failure_report.json`
- `pb019_certification_gap_report.json`
- `pb019_required_actions.json`
- `pb019_certification_explanation.json`

## Fail-Closed Conditions

PB-019 fails closed when:

- any required PB-018 artifact is missing
- any required PB-018 artifact has an invalid schema
- an unsupported governance artifact is present
- PB-018 is verified and there is no failure to explain
- PB-018 is blocked but no blocked reason is available

## Claim Boundary

PB-019 must not claim:

- regulatory certification
- legal certification
- external certification
- production readiness

All outputs must preserve this boundary explicitly.

## Execution

```bash
python3 scripts/pb019_certification_explanation.py \
  governance/evidence/pb018_agent_governance \
  governance/evidence/pb019_certification_explanation
```
