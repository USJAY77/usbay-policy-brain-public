# PB-023 VERIFIED: Governance Metadata Authority

## Purpose

PB-023 establishes one local governance metadata authority for PB release metadata. The authority derives branch names, commit titles, pull request titles, pull request bodies, decision, and status from one PB metadata record.

## Governance Rule

USBAY must not rely on manually corrected PB release metadata when the same metadata can be deterministically generated from a governed source. Missing metadata, malformed metadata, mismatched titles, mismatched PB numbers, mismatched decision/status pairs, empty PR bodies, and unauthorized manual overrides must fail closed.

## Source Metadata

Required fields:

- pb_number
- pb_slug
- pb_title
- decision
- status

Allowed decisions:

- VERIFIED
- REVIEW_REQUIRED
- BLOCKED

Allowed status alignment:

- VERIFIED requires READY FOR REVIEW
- REVIEW_REQUIRED requires AWAITING_APPROVAL
- BLOCKED requires FAIL_CLOSED

## Generated Metadata

The authority generates:

- Branch name: usbay/<pb_slug>
- Commit title: PB-XXX <decision>: <pb_title>
- PR title: PB-XXX <decision>: <pb_title>
- PR body with required governance sections
- Decision
- Status

Required title formats:

- PB-XXX VERIFIED: Full Governance Title
- PB-XXX REVIEW_REQUIRED: Full Governance Title
- PB-XXX BLOCKED: Full Governance Title

## Required PR Body Sections

Every generated PR body must include:

- RISK
- MECHANISM
- GAP
- AUDIT
- IMPACT
- Decision
- Status

## Fail-Closed Conditions

The authority blocks when:

- metadata source is missing
- required metadata field is missing
- PB number is invalid
- PB slug is malformed
- PB title is missing or incomplete
- decision is invalid
- status is invalid
- decision and status are misaligned
- PR title is empty
- PR title is malformed
- commit title is empty
- commit title does not match PR title
- PB number in generated metadata does not match source metadata
- PR body is empty
- PR body is missing required sections
- manual override is attempted without explicit governance override authorization

## Forbidden Behavior

PB-023 does not:

- bypass branch protection
- auto-approve reviews
- admin-merge pull requests
- claim legal certification
- claim regulatory certification
- claim production readiness

## Audit Evidence

PB-023 generates local audit evidence:

- governance/evidence/pb023_metadata_authority_report.json
- governance/evidence/pb023_generated_pr_body.md
- governance/evidence/pb023_generated_commit_title.txt
- governance/evidence/pb023_generated_pr_title.txt
- governance/evidence/pb023_enforcement_report.json

Decision: VERIFIED

Status: READY FOR REVIEW
