# PB-021 Governance Release Automation

PB-021 provides a local release automation helper for PB governance controls.
The helper reduces manual terminal and GitHub work while preserving fail-closed
validation, branch governance, required checks, and human approval.

PB-021 does not bypass branch protection, use admin override, auto-approve
reviews, delete protected branches, or claim regulatory, legal, external, or
production certification.

## Script

`scripts/usbay_pb_release.py`

## Required Inputs

The release helper requires PB metadata:

- PB number
- PB slug
- PB title
- decision
- status

For PB-021, the metadata is:

```text
pb_number: 21
pb_slug: governance-release-automation
pb_title: Governance Release Automation
decision: VERIFIED
status: READY FOR REVIEW
```

From that metadata the helper automatically generates:

```text
PR title: PB-021 VERIFIED: Governance Release Automation
Commit message: PB-021 VERIFIED: Governance Release Automation
Branch name: governance/governance-release-automation
Document path: docs/governance/PB021_GOVERNANCE_RELEASE_AUTOMATION.md
Test path: tests/test_pb021_governance_release_automation.py
```

Allowed decision values:

- `VERIFIED`
- `BLOCKED`
- `REVIEW_REQUIRED`

Allowed status values:

- `READY FOR REVIEW`
- `FAIL_CLOSED`
- `AWAITING_APPROVAL`

Decision/status alignment is mandatory:

- `VERIFIED` requires `READY FOR REVIEW`
- `BLOCKED` requires `FAIL_CLOSED`
- `REVIEW_REQUIRED` requires `AWAITING_APPROVAL`

The generated PB title must use this exact governance format:

```text
PB-XXX VERIFIED: Full Governance Title
PB-XXX BLOCKED: Full Governance Title
PB-XXX REVIEW_REQUIRED: Full Governance Title
```

For other PB controls, the equivalent format is:

```text
PB-XXX VERIFIED: Full Governance Title
```

The commit message must exactly match the PB title. A missing title, malformed
title, lowercase or incomplete title, missing commit message, or commit message
that differs from the PB title fails closed before branch, commit, push, or PR
operations can run.

Manual title, branch, commit message, or PR body override is blocked unless
`--allow-governance-override` is explicitly passed. The legacy
`--allow-title-override` flag remains accepted as an alias. Even with an
override flag, title format, commit/title equality, non-empty PR body, and
governance section validation still apply.

The PR body is generated automatically and must include these governance
sections:

- `RISK`
- `MECHANISM`
- `GAP`
- `AUDIT`
- `IMPACT`
- `Decision`
- `Status`

The generated PR body always includes:

```text
## Decision
VERIFIED

## Status
READY FOR REVIEW
```

or:

```text
## Decision
BLOCKED

## Status
FAIL_CLOSED
```

or:

```text
## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL
```

## Required PB Files

Before commit, the helper verifies that the PB control has local files for:

- governance documentation
- release or validation script
- focused unit tests

For PB-021, the script artifact is `scripts/usbay_pb_release.py`.

## Fail-Closed Controls

The helper blocks when:

- the PR title is missing
- the PR title does not start with `PB-XXX VERIFIED:`
- the commit message is missing
- the commit message does not exactly match the PB title
- the PR body is empty
- manual release metadata is supplied without `--allow-title-override`
- manual release metadata is supplied without `--allow-governance-override`
- decision/status values are invalid
- decision/status values do not align
- required PB files are missing
- the working tree is clean and no PB files exist
- the current branch is `main` or `master`
- the current branch does not match the requested PB branch in dry-run mode
- branch switching or creation fails in real mode
- focused tests fail
- `py_compile` fails
- `git diff --check` fails
- conflict markers are detected
- required PR body sections are missing
- required check names are not supplied before real auto-merge
- required checks are absent from check output

## Real Release Path

In non-dry-run mode, PB-021 performs:

1. Validate PR body sections.
2. Verify required PB files exist.
3. Verify current branch is not protected.
4. Create or switch to the PB branch.
5. Run `py_compile` on PB Python files.
6. Run focused PB pytest files.
7. Run `git diff --check`.
8. Scan PB files for conflict markers.
9. Stage PB files.
10. Commit with the requested PB title and governance metadata.
11. Push the PB branch.
12. Create a PR using the supplied governance body.
13. Watch PR checks.
14. Request auto-merge only after required check names are present.

## Human Approval Boundary

PB-021 never approves its own PR and never bypasses required reviews.
Auto-merge may only be requested after required checks are visible. Branch
protection and required approvals remain external GitHub governance controls.

## Dry-Run Mode

Dry-run mode performs local validation planning without:

- changing branches
- staging files
- committing
- pushing
- creating a PR
- watching checks
- enabling auto-merge

Dry-run mode may be executed from any non-protected branch. It returns the
generated governed PB branch name without switching branches. Real mode creates or
switches to the generated PB branch before validation and release operations.

## Claim Boundary

PB-021 must not claim:

- regulatory certification
- legal certification
- external certification
- production readiness
