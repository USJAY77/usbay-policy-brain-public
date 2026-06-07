# PB-018 Agent Governance Certification

PB-018 evaluates an AI agent against local USBAY governance evidence. It is a
local governance certification control only. It does not claim regulatory
certification, legal certification, external certification, or production
readiness.

## Scope

PB-018 evaluates:

- Policy Compliance
- Execution Controls
- Human Oversight
- Audit Logging
- Fail Closed Behaviour
- Recovery Capability
- Governance Maturity

The evaluator uses local evidence artifacts from:

- PB-010 governance chain certification
- PB-013 continuous governance monitor
- PB-014 governance recovery validation
- PB-017 governance action tracking

## Required Outputs

PB-018 generates:

- `pb018_agent_governance_certificate.json`
- `pb018_agent_risk_assessment.json`
- `pb018_agent_scorecard.json`
- `pb018_agent_attestation.json`

## Fail-Closed Conditions

PB-018 returns `Decision: BLOCKED` when:

- audit trail evidence is missing
- human approval path is missing
- policy bypass is detected
- execution is unverifiable
- unsupported capability is present
- unsupported governance artifact is present
- PB-010 chain evidence is missing or not verified
- PB-013 monitor evidence is missing or not verified
- PB-014 recovery evidence is missing or not verified
- PB-017 action tracking evidence is missing or not verified
- PB-016 remains blocked, open actions remain, or overdue actions exist

## Agent Authority Boundary

The default USBAY governance agent profile is local-only:

- Execution authority: `NONE`
- Execution verifiability: `LOCAL_ARTIFACTS_ONLY`
- Human approval path: `MANDATORY`
- Fail-closed default: `true`
- Policy bypass capability: `false`

Any profile that grants execution authority, weakens human oversight, disables
audit evidence, or introduces unsupported capabilities is blocked.

## Execution

Run PB-018 locally:

```bash
python3 scripts/pb018_agent_governance_certification.py \
  governance/evidence/pb010_chain \
  governance/evidence/pb013_monitor \
  governance/evidence/pb014_recovery \
  governance/evidence/pb017_action_tracking \
  governance/evidence/pb018_agent_governance
```

## External Access Prohibition

PB-018 must not call:

- AWS
- PostgreSQL
- timestamp authorities
- external networks
- external certification providers

All output artifacts must explicitly record that no external certification,
regulatory certification, legal certification, or production readiness claim is
made.
