# Notion Governance Navigation Policy

Purpose: define Notion as a governance navigation and coordination layer only, while preserving the GitHub repository as the authoritative source of truth.

Runtime impact: none.

Gateway impact: none.

Policy enforcement impact: none.

Certification claim: prohibited.

Authoritative architecture duplication from GitHub: prohibited.

## Current Certification State

BLOCKER-001 = CLOSED.

BLOCKER-002 = PARTIAL.

BLOCKER-003 = OPEN.

Certification Status = BLOCKED.

This policy does not close BLOCKER-003.

This policy does not create a certification claim.

## Authority Boundary

The GitHub repository is the authoritative source for:

- Governance policies.
- Architecture decisions.
- Certification decisions.
- Evidence packages.
- Certification blocker registers.
- Traceability matrices.
- Runtime implementation references.
- Validation scripts and tests.
- Audit records committed to the repository.

Notion is informational and navigational only.

Notion may coordinate work, link to source files, summarize current status, and help reviewers find repository evidence.

Notion must not become the source of truth for governance, architecture, certification, evidence, enforcement, audit, or production-readiness decisions.

## Certification Decision Rule

Certification decisions must originate in GitHub.

Certification status must be determined from repository evidence, committed blocker registers, traceability matrices, validation outputs, and audit records.

Notion pages may summarize certification status only when they link back to the exact GitHub source files supporting that status.

If a Notion page claims a certification decision without a GitHub source link:

Decision: BLOCKED.

## Architecture Decision Rule

Architecture decisions must originate in GitHub.

Architecture claims must be supported by repository files, implementation evidence, test evidence, and audit evidence where applicable.

Notion pages may link to architecture documents and summarize their status, but must not duplicate or override authoritative GitHub architecture content.

If Notion architecture content conflicts with GitHub:

Decision: BLOCKED.

GitHub remains authoritative until a governed repository change updates the source-of-truth decision.

## Evidence Package Rule

Evidence packages must originate in GitHub or in a governed evidence package referenced from GitHub.

Notion may link to evidence package locations, checklists, or status summaries.

Notion must not host the authoritative copy of:

- Provider evidence.
- Audit receipts.
- Certification evidence.
- Runtime validation evidence.
- Traceability matrices.
- Blocker closure records.

If Notion references evidence that is not present in GitHub or a governed evidence package:

Decision: BLOCKED.

## Link-Back Requirement

Every Notion governance page that summarizes USBAY governance status must link back to the relevant GitHub source files.

Required link-back targets include, where applicable:

- Source-of-truth policy.
- Certification blocker register.
- Claim-level traceability matrix.
- Architecture source manifest.
- Audit dossier.
- Evidence package directory.
- Validation script or test file.

If a Notion page lacks the required GitHub source link:

Decision: BLOCKED.

## Status Summary Boundary

Notion may summarize status, including:

- BLOCKER-001 = CLOSED.
- BLOCKER-002 = PARTIAL.
- BLOCKER-003 = OPEN.
- Certification Status = BLOCKED.

Notion may not override these statuses.

Status changes must be made through a governed GitHub change, with evidence, validation, commit history, and review.

## Conflict Rule

If Notion and GitHub disagree:

1. Treat the state as unsafe.
2. Use the GitHub repository as the authoritative source.
3. Mark the disputed claim as blocked until reconciled in GitHub.
4. Record the conflict in a repository issue, audit note, blocker register, or traceability update as appropriate.
5. Do not rely on Notion to approve, certify, close blockers, or override missing evidence.

Conflict outcome:

Decision: BLOCKED.

## Fail-Closed Rule

If Notion contains a governance, architecture, certification, evidence, audit, or production-readiness claim that cannot be traced to GitHub:

Decision: BLOCKED.

If Notion claims a blocker is closed but GitHub does not record closure evidence:

Decision: BLOCKED.

If Notion references provider evidence that is missing from GitHub or a governed evidence package:

Decision: BLOCKED.

If Notion and GitHub disagree:

Decision: BLOCKED.

Human approval is not evidence.

Notion status text is not evidence.

Only repository evidence or governed evidence packages referenced by GitHub may support governance decisions.
