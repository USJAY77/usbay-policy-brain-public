## PURPOSE

Implement the USBAY execution decision engine for governed computer-use actions.

## RISK

Without a deterministic decision engine, computer-use actions could proceed without a clear `ALLOW`, `BLOCK`, `HUMAN_REVIEW`, or `FAIL_CLOSED` decision.

## POLICY LINK

- AGENTS.md fail-closed governance
- AGENTS.md human oversight
- AGENTS.md audit-first engineering
- policy/computer_use_policy.json
- docs/architecture/USBAY_GOVERNED_COMPUTER_USE_RUNTIME.md

## REQUIRED APPROVALS

- USBAY-AUDIT review required before merge.
- USBAY-GLOBAL23 review required before merge.
- No deployment, provider activation, desktop execution, or browser execution is authorized.

## GOVERNANCE CHECKS

- Action contract requires action type, target, screen summary, provider response, approval state, and policy version.
- Risk classifier identifies low, medium, high, and unknown risk.
- High-risk examples are classified as high risk.
- Low risk maps to `ALLOW`.
- Medium and high risk map to `HUMAN_REVIEW`.
- Unknown risk and missing policy map to `FAIL_CLOSED`.
- Unsupported action maps to `BLOCK`.
- Decision output includes decision ID, decision, reason, risk level, policy version, audit hash, and timestamp.

## AUDIT

PB-158 decision outputs include deterministic audit hashes over decision metadata. Evidence is recorded under `governance/evidence/pb158/`.

## IMPACT

This is a local decision layer only. It does not execute browser actions, desktop actions, provider calls, deployments, or external network calls.

## Decision

VERIFIED

## Status

READY_FOR_REVIEW
