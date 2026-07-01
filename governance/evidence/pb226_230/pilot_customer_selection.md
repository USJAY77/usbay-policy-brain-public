# PB-226 Pilot Customer & Use-Case Selection

Decision: VERIFIED
Status: READY_FOR_REVIEW

## Approved Pilot Workflow

GitHub -> USBAY Gateway -> Human Approval -> Codex

## Selected Customer Profile

customer_id: pilot-customer-redacted

The selected pilot customer profile is a regulated engineering team that needs governed AI assistance for repository review while preserving policy validation, human approval, and audit evidence.

## Use Case

One limited workflow may be reviewed for pilot readiness: a GitHub event is evaluated by the USBAY Gateway, blocked pending explicit Human Approval, and only then routed to Codex for the approved action window.

## Boundaries

- Default state is `BLOCKED`.
- No real live execution.
- No connector activation.
- No customer data, personal data, secrets, tokens, or private keys in logs.
- Human approval is required before any live action.
