## PURPOSE

Create the USBAY Execution Contract Layer that formally binds Vision Provider, Decision Engine, Approval Layer, Audit Chain, and Execution Runtime into one tamper-evident execution contract.

## RISK

Without a formal execution contract, decision/execution drift can occur, approval replay is possible, audit chains become ambiguous, runtime implementations may diverge, and policy enforcement becomes inconsistent.

## POLICY LINK

- AGENTS.md fail-closed governance
- AGENTS.md human oversight
- AGENTS.md audit-first engineering
- runtime/computer_use/decision_engine.py
- runtime/computer_use/decision_provenance.py

## REQUIRED APPROVALS

- USBAY-AUDIT review required before merge.
- USBAY-GLOBAL23 review required before merge.
- No deployment, browser execution, desktop execution, provider activation, or external API call is authorized.

## GOVERNANCE CHECKS

- Contract schema includes contract ID, decision ID, audit chain ID, policy version, risk level, action type, target, approval requirement, approval token, approval expiration, creation timestamp, and status.
- Missing policy fails closed.
- Missing approval token fails closed when approval is required.
- Expired approval fails closed.
- Missing decision fails closed.
- Missing or invalid audit chain fails closed.
- Unsupported action blocks.
- Denied approval blocks.
- Explicit deny policy blocks.
- Medium/high/privileged actions return human review while approval is pending.
- Valid allow path requires decision allow, approval requirements satisfied, verified audit chain, and valid contract.

## AUDIT

PB-160 contract audit records include contract ID, decision ID, audit chain ID, approval state, approval token hash, previous hash, current hash, and timestamp.

## IMPACT

This is a local contract validation layer only. It does not execute browser actions, desktop actions, provider calls, deployments, or external network calls.

## Decision

VERIFIED

## Status

READY_FOR_REVIEW
