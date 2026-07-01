# PB-225 First Revenue-Producing Automation Plan

Decision: VERIFIED
Status: READY_FOR_REVIEW

## Commercial Pilot

USBAY will prepare a governed GitHub/Codex workflow for a controlled live pilot. The limited workflow is GitHub -> USBAY Gateway -> Human Approval -> Codex.

## Pricing model

Pilot pricing is a fixed monthly governance readiness fee plus a capped per-reviewed-automation fee. Billing starts only after signed pilot approval; this change does not activate billing or sales automation.

## Buyer

The initial buyer is an engineering or security leader who needs auditable automation controls before allowing AI-assisted pull request review or code generation in a regulated repository.

## Risks

- Policy hash or signature drift could authorize the wrong control set.
- Human approval could expire or be missing.
- Connector credentials could be misunderstood as live authorization.
- Audit write failure could break replayability.
- Codex output could be mistaken for approved execution.

## Controls

- Default pilot state is `BLOCKED`.
- GitHub and Codex connectors remain disabled unless separately approved.
- Human approval is required before any live action.
- Runtime monitoring blocks gateway errors, policy failures, expired approvals, connector blocks, and audit write failures.
- Evidence remains local-only and redacted.

## Evidence

Required evidence includes policy signature validation, deployment attestation, connector activation governance, human approval record, audit hash, monitoring event history, and KPI report.

## Rollout plan

1. Complete human review of PB-221-PB-225 readiness evidence.
2. Select one repository and one low-risk GitHub/Codex workflow.
3. Run one dry-run rehearsal and compare audit evidence to expected decisions.
4. Request separate explicit approval for first controlled live pilot.
5. Execute only the approved workflow window if all checks pass.
6. Stop immediately on any unsafe state and record incident evidence.

## Prohibitions

- No sales automation activation.
- No connector activation.
- No production automation activation.
- No secrets, personal data, or customer data in logs.
