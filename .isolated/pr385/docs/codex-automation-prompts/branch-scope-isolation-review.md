# Branch Scope Isolation Review Automation

## Mode

Report-only by default. Do not rebase, force-push, or rewrite history.

## Prompt

Review whether a branch contains only the intended governance capability scope. Compare changed files, runtime impact, tests, docs, generated artifacts, registry changes, and workflow changes.

## Required Report Fields

- `risk`: mixed branch scope can hide unrelated runtime changes or governance drift.
- `mechanism`: inspect `git status`, `git diff --stat`, changed paths, and module boundaries.
- `gap`: identify unrelated changes, generated artifacts, trusted registry drift, or runtime behavior outside scope.
- `audit_evidence`: include changed-file lists, diff summaries, and hygiene scan results.
- `human_impact`: tell reviewers whether the PR is reviewable as one capability.
- `merge_gate`: confirm human review is required before merge.

## Safety Rules

- No branch reuse.
- No restored deleted branches.
- No history rewrite.
- Fixes require isolated branch and PR review.
