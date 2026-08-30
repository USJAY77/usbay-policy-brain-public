# PB-155 Human Approval Workflow for Governed Computer-Use Runtime

## Purpose

PB-155 adds a fail-closed human approval boundary around the USBAY Governed Computer-Use Runtime so high-risk computer actions cannot execute autonomously.

## Implemented Controls

- Approval queue for high-risk computer-use actions.
- Approval request schema with required fields and fail-closed missing-field behavior.
- Short-lived approval token bound to action ID and action hash.
- Approval reason required for approvals and denials.
- Deny path that blocks execution and preserves approval audit hash.
- Replay protection for consumed approval tokens.
- Expiration handling for stale approval tokens.
- Audit hash for approval request, approval decision, denial, token consumption, and runtime decision events.
- Evidence export with raw approval tokens redacted.

## Runtime Decision Rules

- LOW `read_screen` remains `ALLOW`.
- Unknown actions `BLOCK`.
- Click/type against high-risk targets return `HUMAN_REVIEW` until approval evidence is provided.
- GitHub merge/delete/deploy targets require `HUMAN_REVIEW`.
- Secret-like typed text `BLOCK`.
- Missing policy returns `FAIL_CLOSED`.
- Expired approval tokens `BLOCK`.
- Reused approval tokens `BLOCK`.
- Denied approvals `BLOCK`.
- Approved actions proceed only when policy, approval token, action hash, expiration, and audit evidence validate.

## Validation Result

Decision: VERIFIED

Status: READY FOR REVIEW

No production activation, live provider call, credential use, deployment, merge, branch deletion, autonomous execution, or raw screenshot logging was performed.
