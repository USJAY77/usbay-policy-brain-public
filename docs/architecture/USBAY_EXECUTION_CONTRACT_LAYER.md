# USBAY Execution Contract Layer

## Purpose

The USBAY Execution Contract Layer binds the governed computer-use flow into one tamper-evident contract:

Vision Provider -> Decision Engine -> Approval Layer -> Audit Chain -> Execution Runtime

USBAY remains the execution authority. Humans remain the approval authority. No execution may occur without a valid execution contract.

## Contract Schema

Each execution contract records:

- `contract_id`
- `decision_id`
- `audit_chain_id`
- `policy_version`
- `risk_level`
- `action_type`
- `target`
- `approval_required`
- `approval_token`
- `approval_expires_at`
- `created_at`
- `status`

Valid statuses are `ALLOW`, `BLOCK`, `HUMAN_REVIEW`, and `FAIL_CLOSED`.

## Fail-Closed Rules

The contract returns `FAIL_CLOSED` when:

- policy is missing
- approval token is missing for an approved high-risk action
- approval token is expired
- decision is missing
- audit chain is missing or invalid
- contract is malformed
- upstream decision or provider is fail-closed

## Block Rules

The contract returns `BLOCK` when:

- approval is denied, revoked, expired, or blocked
- action is unsupported
- decision or provider explicitly blocks the action

## Human Review Rules

The contract returns `HUMAN_REVIEW` when a medium-risk, high-risk, or privileged target is awaiting human approval.

## Allow Rules

The contract returns `ALLOW` only when:

- decision is `ALLOW`
- provider response is `ALLOW`
- approval requirements are satisfied
- audit chain is verified
- contract is valid

## Tamper-Evident Audit Binding

Every contract records:

- `contract_id`
- `decision_id`
- `audit_chain_id`
- `approval_state`
- `approval_token_hash`
- `previous_hash`
- `current_hash`
- `timestamp`

Contract hash chaining starts at `GENESIS`. Replayed or modified contract records break chain verification.

## Runtime Boundary

PB-160 does not deploy, activate providers, execute browser actions, execute desktop actions, or call external APIs. It creates a local validation layer only.
