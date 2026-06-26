# PB-047 GitHub Pilot Onboarding Evidence Package

## Decision
REVIEW_READY

## Status
READY_FOR_REVIEW

## Evidence Boundary
This PB populates the GitHub pilot onboarding package for governance review only. It does not create a GitHub App, generate credentials, call GitHub APIs, mutate repositories, or activate production.

## Is The Onboarding Package Fully Populated?
Yes. The eight PB-046 package artifacts are populated with concrete review values for the pilot repository `USJAY77/usbay-policy-brain-public`.

## Required Onboarding Artifacts Present
- `business_justification.json`
- `risk_assessment.json`
- `permission_manifest.json`
- `repository_scope.json`
- `installation_scope.json`
- `rollback_plan.json`
- `audit_authority_record.json`
- `credential_authority_record.json`

## Proposed Scope
- Pilot repository: `USJAY77/usbay-policy-brain-public`
- GitHub App installation type: repository-scoped
- First pilot capability: create review-only governance issue
- Initial permissions: `issues:write` and read-only metadata
- Production mutations: denied until separate production readiness review

## Approvals Outstanding
- `USBAY-AUDIT`
- `USBAY-GLOBAL23`

## Can The Package Be Submitted For Governance Review?
Yes. The package is review-ready and can be submitted to the required approvers. It does not authorize GitHub App creation until those approvals are recorded.

## Final Decision
`REVIEW_READY`

## Generated PR Body
## PURPOSE
PB-047 populates the GitHub pilot onboarding package defined by PB-046 so it can be submitted for governance review before any GitHub App is created.

## RISK
The package defines future GitHub App authority over the USBAY repository. If permission scope, repository scope, approvals, rollback, credential authority, or audit authority are incomplete, USBAY could create an ungoverned repository mutation path.

## POLICY LINK
AGENTS.md fail-closed, audit-first engineering, human oversight, branch governance, network governance, and secret/data hygiene rules. PB-041 GitHub connector authority, PB-042 production connector design, PB-043 onboarding plan, PB-044 readiness execution, PB-045 creation authority, and PB-046 package templates.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 approval remain required before GitHub App creation. This package is review-ready but not approved for app creation, credential generation, API calls, repository mutation, or production activation.

## GOVERNANCE CHECKS
JSON evidence must parse. Metadata, governance sections, package artifacts, approval status, missing evidence, diff hygiene, conflict marker scan, and unresolved-template scan must pass.

## AUDIT
PB-047 generates governance/evidence/pb047/github_pilot_onboarding_evidence_package.json, governance/evidence/pb047/github_pilot_onboarding_summary.md, generated_commit_title.txt, generated_pr_title.txt, and generated_pr_body.md.

## IMPACT
USBAY now has a populated GitHub App onboarding review package while preserving fail-closed blocking until required approvers review and approve it.

## Decision
VERIFIED

## Status
READY_FOR_REVIEW
