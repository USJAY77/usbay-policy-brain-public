## PURPOSE

Build the human approval boundary for the USBAY Governed Computer-Use Runtime so high-risk computer actions cannot execute autonomously.

## RISK

Uncontrolled computer-use agents can click, type, approve, merge, delete, deploy, or expose secrets without human consent. Missing approval controls could allow unauthorized state changes or unaudited execution.

## POLICY LINK

- AGENTS.md fail-closed governance
- AGENTS.md human oversight
- AGENTS.md audit-first engineering
- docs/architecture/USBAY_GOVERNED_COMPUTER_USE_RUNTIME.md
- policy/computer_use_policy.json

## REQUIRED APPROVALS

- USBAY-AUDIT review required before merge.
- USBAY-GLOBAL23 review required before merge.
- No autonomous execution approval is granted by this change.

## GOVERNANCE CHECKS

- Approval queue implemented.
- Approval request schema defined.
- Approval token issuance, expiration, denial, replay protection, and evidence export implemented.
- Missing policy fails closed.
- Expired approval tokens block execution.
- Reused approval tokens block execution.
- Denied approvals block execution.
- Secret-like typed text blocks execution.
- Approved high-risk action requires policy, approval, and audit validation.

## AUDIT

- Approval requests record audit hashes.
- Approval decisions record audit hashes.
- Denials record audit hashes.
- Token consumption records audit evidence.
- Runtime decisions record chained audit hashes.
- Approval evidence export redacts raw tokens.

## IMPACT

The computer-use runtime remains dry-run and local-only. The change adds a reviewable approval boundary for high-risk actions without enabling live provider calls, credentials, deployment, branch deletion, production activation, or autonomous external mutation.

## Decision

VERIFIED

## Status

READY FOR REVIEW
