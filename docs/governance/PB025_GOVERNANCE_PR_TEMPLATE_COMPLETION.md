# PB-025 VERIFIED: Governance PR Template Completion

## Purpose

PB-025 prevents incomplete governance pull request templates from being used for PB releases.

## Control

The PR template validator generates a fully populated governance PR body and validates it before PR creation. It fails closed if any unresolved placeholder remains or if any required section is missing or empty.

## Required Sections

- PURPOSE
- RISK
- POLICY LINK
- REQUIRED APPROVALS
- GOVERNANCE CHECKS
- AUDIT
- IMPACT
- Decision
- Status

## Forbidden Placeholders

Generated PR bodies must never contain:

- Describe what is changing and why.
- System impact:
- User impact:
- Risk level:
- Policy ID:
- Policy version / hash:

## Fail-Closed Conditions

The validator blocks when:

- PR body is missing
- required section is missing
- required section is empty
- unresolved template placeholder remains
- required metadata field is empty
- required approvals are missing
- governance checks are missing
- decision and status are misaligned

## Governance Boundaries

PB-025 does not bypass branch protection, admin review, required approvals, or merge rules. It does not auto-approve or admin-merge pull requests.

## Evidence

PB-025 generates:

- governance/evidence/pb025_template_validation_report.json
- governance/evidence/pb025_generated_pr_body.md

Decision: VERIFIED

Status: READY FOR REVIEW
