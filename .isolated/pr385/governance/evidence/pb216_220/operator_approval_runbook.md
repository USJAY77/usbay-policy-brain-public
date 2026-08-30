# PB-218 Operator Approval Runbook

Decision: VERIFIED
Status: READY_FOR_REVIEW

## High-Risk Automation

High-risk automation includes any non-read action, public posting, connector mutation, deployment action, regulator export, credential rotation, or action that can alter governance state.

## Manual Approval Steps

1. Confirm the request has a valid policy hash, active policy signature metadata, and deployment attestation record.
2. Confirm the connector remains `DISABLED` or `DRY_RUN`; if the connector is live-enabled, stop and mark `FAIL_CLOSED`.
3. Review redacted evidence only. Do not store secrets, tokens, passwords, private keys, raw approvals, or user data.
4. Confirm approval expiry is in the future and the human reviewer is explicitly identified.
5. Record manual review intent in local evidence. No real approval execution is performed by this readiness layer.
6. If any evidence is missing, stale, malformed, or ambiguous, return `FAIL_CLOSED`.

## Prohibited Actions

- No real approval execution.
- No deployment.
- No connector activation.
- No browser, desktop, external API, or production action.
- No secrets or raw user data in logs.

## Operator Outcome

The only allowed readiness outcome is evidence-backed review. Controlled live pilot remains blocked until human approval, signature validation, deployment attestation, and credential governance are independently reviewed.
