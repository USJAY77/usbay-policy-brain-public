# USBAY Codex Automation Templates

These templates define USBAY-safe Codex automation prompts. They are report-only by default and must not mutate governance state, merge code, write to `main`, grant policy authority, expose secrets, or log raw payloads.

## Mandatory Safety Gates

Every automation must:

- run in report-only mode unless a human explicitly requests a follow-up implementation
- produce findings, evidence, and recommended next steps without changing runtime behavior
- never auto-merge or push directly to `main`
- never log secrets, private keys, raw nonces, approval contents, raw governance payloads, OCSP/CRL bytes, or runtime credentials
- never claim verification without citing the validation command or artifact that proves it
- treat missing evidence as fail-closed
- require an isolated branch and pull request for any proposed fix
- confirm human review is required before merge

## Prompt Template Inventory

- [Governance Drift Detection](codex-automation-prompts/governance-drift-detection.md)
- [Fail-Closed Coverage Audit](codex-automation-prompts/fail-closed-coverage-audit.md)
- [Runtime Integrity Review](codex-automation-prompts/runtime-integrity-review.md)
- [Audit Lineage Validation](codex-automation-prompts/audit-lineage-validation.md)
- [Registry Mutation Detection](codex-automation-prompts/registry-mutation-detection.md)
- [Replay Protection Coverage](codex-automation-prompts/replay-protection-coverage.md)
- [Regulator Export Consistency](codex-automation-prompts/regulator-export-consistency.md)
- [Evidence Chain Integrity Audit](codex-automation-prompts/evidence-chain-integrity-audit.md)
- [Branch Scope Isolation Review](codex-automation-prompts/branch-scope-isolation-review.md)
- [Forbidden Runtime File Detection](codex-automation-prompts/forbidden-runtime-file-detection.md)

## Standard Report Format

Each automation report must include:

- `risk`: what can go wrong if the control fails
- `mechanism`: how the automation inspected the control
- `gap`: any missing, stale, ambiguous, or unverifiable evidence
- `audit_evidence`: commands, file paths, hashes, or test results that support the finding
- `human_impact`: what an operator, reviewer, auditor, or customer should understand
- `merge_gate`: explicit statement that human review is required before merge

## Fix Workflow

If an automation identifies a fix:

1. Report the issue and evidence first.
2. Recommend the smallest safe change.
3. Create no code changes unless a human explicitly authorizes implementation.
4. Use an isolated branch for any implementation.
5. Open a PR with validation evidence and fail-closed impact.
6. Require human review before merge.
