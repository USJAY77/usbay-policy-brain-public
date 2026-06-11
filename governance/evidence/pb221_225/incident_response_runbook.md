# PB-223 Incident Response Runbook

Decision: VERIFIED
Status: READY_FOR_REVIEW

## Monitored Events

- `gateway_error`
- `policy_fail`
- `approval_expired`
- `connector_blocked`
- `audit_write_failed`

## Response Rule

Every unsafe state returns `BLOCKED`. No live retry, connector activation, browser action, desktop action, external API call, or production automation may run from this readiness layer.

## Manual Response Steps

1. Stop the pilot workflow and mark the current action `BLOCKED`.
2. Preserve redacted local evidence with hashes only.
3. Confirm no secrets, tokens, passwords, private keys, personal data, or customer data were written to logs.
4. Classify the event using the runtime monitoring contract.
5. Require human review before any new pilot attempt.
6. If audit writing failed, block all downstream actions until audit storage is restored and reviewed.

## Escalation

Escalate to a human governance owner for policy failures, expired approvals, connector blocks, and audit write failures. A controlled live pilot may resume only after new explicit approval and updated evidence.
