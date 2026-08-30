# PB-043 GitHub Connector Onboarding Plan

## Decision
READY_FOR_ONBOARDING

## Status
READY_FOR_REVIEW

## Evidence Boundary
This PB is onboarding design only. It does not create a GitHub App, create credentials, call GitHub APIs, mutate repositories, or activate production.

## Can GitHub App Onboarding Be Executed Safely?
Yes, but only through the phased fail-closed sequence defined in this PB.

Live mutation remains blocked until credential authority, secret storage, permission mapping, approval enforcement, audit generation, post-action receipt capture, rollback, and pilot validation evidence exist.

## Exact Onboarding Sequence
1. GitHub App Creation
2. Credential Authority
3. Secret Storage
4. Permission Mapping
5. Approval Workflow
6. Pilot Repository Validation
7. Production Readiness Review

## GitHub App Requirements
- Installation scope: only repositories explicitly approved for USBAY governance.
- Repository scope: start with one pilot repository.
- Permission scope: minimum permission required for one pilot capability.
- Webhooks: signature verification, replay protection, and fail-closed handling are required before production use.
- Token lifetime: use short-lived installation tokens per execution session.
- Rotation: rotate private keys at least every 90 days or immediately after incident indicators.

## Secret Governance
- Storage authority: approved secret manager or protected deployment secret store with audit access.
- Access authority: connector runtime identity and designated secret custodians only.
- Rotation authority: USBAY governance authority and credential owner.
- Revocation authority: USBAY governance authority.
- Incident response path: block connector actions, revoke affected credential, rotate key, audit revocation, verify no active token remains trusted, and complete evidence review.

## Governance Controls Before First Live Mutation
- Repository-scoped GitHub App.
- External secret storage.
- Credential authority record.
- Permission mapping for the exact pilot capability.
- Human approval enforcement.
- Policy reference.
- Approval reference.
- Actor attribution.
- Pre-action audit.
- Post-action GitHub receipt.
- Rollback path.
- Fail-closed negative tests.

## Evidence Required
- GitHub App authority record.
- Credential authority record.
- Secret reference hash record.
- Permission mapping record.
- Approval workflow record.
- Pre-action audit record.
- Post-action GitHub receipt.
- Pilot validation report.
- Fail-closed negative test record.
- Production readiness review record.

## Final Decision
`READY_FOR_ONBOARDING`

This means the onboarding plan is ready to govern future onboarding work. It does not mean the connector is production-active or authorized for live mutation.

## Generated PR Body
## PURPOSE
PB-043 defines the governance-controlled onboarding sequence for the first production GitHub connector using the GitHub App model selected by PB-042.

## RISK
GitHub onboarding can create mutation authority over branches, pull requests, releases, rulesets, protections, and secrets. If onboarding skips credential authority, secret governance, approval enforcement, audit generation, or fail-closed validation, USBAY could create an ungoverned execution path.

## POLICY LINK
AGENTS.md fail-closed, audit-first engineering, human oversight, branch governance, network governance, and secret/data hygiene rules. PB-038 connector framework, PB-040 connector readiness, PB-041 GitHub connector authority, and PB-042 GitHub production connector design.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 review are required before merge. Future GitHub App creation, credential storage, live API calls, or repository mutation require separate approval and evidence.

## GOVERNANCE CHECKS
JSON evidence must parse. Summary must answer onboarding safety, exact sequence, controls before first live mutation, required evidence, and final decision. Diff hygiene, conflict marker scan, metadata validation, and required governance section checks must pass.

## AUDIT
PB-043 generates governance/evidence/pb043/github_connector_onboarding_plan.json and governance/evidence/pb043/github_connector_onboarding_summary.md. It defines phase evidence, audit outputs, fail-closed conditions, and completion criteria without creating credentials or performing external actions.

## IMPACT
USBAY gains a controlled path from design to GitHub App onboarding while keeping all live mutations blocked until every phase produces required evidence.

## Decision
VERIFIED

## Status
READY_FOR_REVIEW
