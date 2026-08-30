# PB-026 VERIFIED: Governance PR Body Integration

## Purpose

PB-026 ensures generated governance PR bodies replace the legacy GitHub pull request template for PB governance PRs.

## Finding

Repository evidence showed `.github/pull_request_template.md` still contained unresolved placeholder text. If `gh pr create` is run without `--body` or `--body-file`, GitHub can apply that fallback template instead of the generated governance body.

## Control

PB-026 adds a PR body integration validator that:

- validates the generated PR body is complete
- verifies forbidden placeholders are absent
- verifies required sections are populated
- verifies the repository fallback template no longer contains legacy placeholders
- fails closed when PR creation does not supply the generated body
- fails closed when the wrong body file is supplied
- records fail-closed evidence when an existing open PR body cannot be repaired because GitHub update authority is unavailable

## Required Generated Sections

- PURPOSE
- RISK
- POLICY LINK
- REQUIRED APPROVALS
- GOVERNANCE CHECKS
- AUDIT
- IMPACT
- Decision
- Status

## Fail-Closed Conditions

PB-026 blocks when:

- generated PR body is missing
- generated PR body is incomplete
- unresolved template placeholder remains
- required section is empty
- `gh pr create` omits `--body` or `--body-file`
- `gh pr create` uses the repository fallback template as the body file
- generated body text does not match the expected governance body
- existing open PR repair cannot update the PR body

## Governance Boundaries

PB-026 does not bypass branch protection, auto-approve reviews, admin-merge PRs, or create certification claims.

## Evidence

PB-026 generates:

- governance/evidence/pb026_pr_body_integration_report.json
- governance/evidence/pb026_generated_pr_body.md
- governance/evidence/pb026_existing_pr_body_repair_report.json

Decision: VERIFIED

Status: READY FOR REVIEW
