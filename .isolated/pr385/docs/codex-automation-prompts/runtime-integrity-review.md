# Runtime Integrity Review Automation

## Mode

Report-only by default. Do not change runtime enforcement behavior.

## Prompt

Review runtime integrity controls for startup validation, runtime provenance authority, policy registry checks, forbidden runtime file detection, and fail-closed runtime behavior.

## Required Report Fields

- `risk`: runtime integrity gaps can allow execution under stale, unsigned, or ambiguous governance state.
- `mechanism`: inspect runtime validation entrypoints, startup integrity commands, and diagnostics output.
- `gap`: list any missing validation, fallback allow behavior, or ambiguous authority handling.
- `audit_evidence`: include exact commands such as startup integrity validation and relevant file paths.
- `human_impact`: describe operational consequence for release, incident response, or runtime execution.
- `merge_gate`: confirm human review is required before merge.

## Safety Rules

- Never bypass startup validation.
- Never introduce optimistic runtime success states.
- Never print secrets or raw payloads.
- Proposed fixes require isolated branch and PR review.
