# USBAY Governed AI Collaboration Workflow

This document defines how ChatGPT, Codex, GitHub, and human reviewers collaborate under USBAY governance. It is documentation only. It does not grant runtime authority, merge authority, policy authority, or automation privileges to any AI system.

## Governance Principle

AI systems may assist with analysis, implementation, validation, and remediation planning, but they do not replace GitHub rulesets, CI evidence, policy verification, or human approval.

Human reviewers remain the final approval and merge authority.

## Roles

### ChatGPT

ChatGPT may provide:

- analysis of governance gaps
- task framing and acceptance criteria
- risk assessment
- fail-closed requirements
- review prompts and operator guidance
- validation expectations

ChatGPT must not claim approval authority, merge authority, or source-of-truth status.

### Codex

Codex may provide:

- implementation in an isolated branch
- focused tests and validation runs
- pull request preparation
- remediation suggestions when validation fails
- audit-safe summaries of changed files and validation evidence

Codex must not self-approve, auto-merge, bypass GitHub rulesets, or treat partial validation as complete validation.

### GitHub

GitHub is the source of truth for:

- repository history
- branch rulesets
- pull requests
- commits
- CI results
- reviewer approvals
- audit trail

GitHub Actions and rulesets provide governance evidence, but successful CI alone is not human approval.

### Human Reviewers

Human reviewers provide:

- final governance review
- approval identity
- merge authorization
- policy exception decisions
- release readiness decisions

At least two required human approvals are needed when the repository ruleset or policy requires dual-reviewer governance.

## Explicit Prohibitions

The following are prohibited:

- agent self-approval
- agent auto-merge
- secrets, tokens, private keys, raw payloads, or approval contents in prompts or logs
- bypassing GitHub rulesets
- treating AI review as human approval
- treating generated text as policy authority
- treating local validation as a substitute for required GitHub checks
- merging when reviewer identity is unclear

## Fail-Closed Rules

USBAY collaboration must fail closed when:

- validation is incomplete
- reviewer identity is unclear
- full pytest is skipped, bounded, failed, or unbounded without the gap being disclosed
- policy source is unclear
- CI evidence is missing, stale, contradictory, or unverifiable
- branch ruleset state cannot be resolved
- audit evidence is missing or unsafe

If any of these conditions occur, the work must remain blocked until a human reviewer resolves the gap.

## Audit Evidence Requirements

Each governed AI-assisted change should preserve audit evidence containing:

- PR link
- commit hash
- reviewer approvals
- CI results
- validation gaps
- agent action log
- changed file list
- branch name
- policy or ruleset reference used for review
- human merge decision

Audit evidence must be bounded and redacted. It must not contain secrets, private keys, tokens, raw payloads, or approval contents.

## Example Workflow

```text
1. ChatGPT creates task
   - frames governance objective
   - identifies risks and fail-closed conditions
   - defines validation expectations

2. Codex implements
   - creates or uses one isolated branch for one capability
   - changes only scoped files
   - runs focused validation
   - discloses validation gaps
   - prepares a PR without merging

3. GitHub Actions validates
   - runs required CI
   - enforces rulesets
   - records status checks
   - preserves PR and commit audit trail

4. Two human reviewers approve
   - reviewer identities are visible in GitHub
   - approvals satisfy repository rulesets
   - AI review is not counted as human approval

5. Human merges
   - merge occurs only after required checks and approvals pass
   - merge action is attributable to a human or governed repository process explicitly authorized by humans
   - post-merge audit evidence remains available in GitHub
```

## Required Disclosure Pattern

Every AI-assisted PR summary should disclose:

- what the agent changed
- which validation commands passed
- which validation commands failed
- which validation commands were not run
- whether full pytest completed cleanly
- whether any governance, policy, runtime, or audit behavior changed
- whether human approval is still required

## Non-Goals

This document does not add:

- runtime automation
- auto-merge
- new GitHub Actions workflows
- policy enforcement code
- branch cleanup automation
- reviewer approval automation

Any future automation must be implemented in a separate governed branch and must preserve fail-closed behavior, GitHub rulesets, audit evidence, and human approval.
