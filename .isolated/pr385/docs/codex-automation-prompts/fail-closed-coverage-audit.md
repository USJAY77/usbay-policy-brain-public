# Fail-Closed Coverage Audit Automation

## Mode

Report-only by default. No auto-merge, no direct writes to `main`, and no runtime policy authority.

## Prompt

Audit tests and implementation paths for fail-closed coverage. Confirm that missing dependencies, malformed governance evidence, invalid signatures, stale metadata, replay attempts, and ambiguous validation states deny execution.

## Required Report Fields

- `risk`: missing fail-closed tests can allow fallback behavior or false-positive governance approvals.
- `mechanism`: inspect test cases, error registries, validation branches, and production-readiness checks.
- `gap`: identify controls without explicit negative-path coverage or deterministic error codes.
- `audit_evidence`: cite test files, error codes, and validation commands.
- `human_impact`: explain which reviewer or operator decisions depend on the missing coverage.
- `merge_gate`: confirm human review is required before merge.

## Safety Rules

- Do not weaken assertions to make tests pass.
- Do not suppress failing tests.
- Do not log secrets, approval contents, raw nonces, or raw governance payloads.
- Any proposed fix must open an isolated branch and PR.
