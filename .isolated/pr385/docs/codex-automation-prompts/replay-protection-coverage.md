# Replay Protection Coverage Automation

## Mode

Report-only by default. No runtime mutation and no policy authority.

## Prompt

Audit replay protection across nonce stores, attestation nonces, timestamp replay checks, evidence replay bindings, Merkle proof replay detection, revocation response nonces, and renewal chain replay controls.

## Required Report Fields

- `risk`: replay gaps can allow stale approvals, duplicated evidence, or reused runtime decisions.
- `mechanism`: inspect nonce validation, replay registries, negative-path tests, and deterministic error codes.
- `gap`: list missing replay tests, ambiguous replay behavior, or fallback allow paths.
- `audit_evidence`: cite tests, error codes, and validation outputs.
- `human_impact`: explain whether replay risk affects runtime execution, evidence exports, or audit reliance.
- `merge_gate`: confirm human review is required before merge.

## Safety Rules

- Never weaken nonce validation.
- Never add fallback allow behavior.
- Never log raw nonces.
- Fixes require isolated branch and PR review.
