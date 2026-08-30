# PB-045 GitHub App Creation Authority

## Decision
APPROVED_WITH_CONTROLS

## Status
READY_FOR_REVIEW

## Evidence Boundary
This PB is authority-definition only. It does not create a GitHub App, create credentials, call GitHub APIs, modify repositories, or activate production connectors.

## Can GitHub App Creation Be Approved?
Yes. GitHub App creation can be approved only as non-production onboarding authority and only after mandatory approvals and evidence requirements are complete.

Creation does not authorize repository mutations, branch deletion, pull request merge, release creation, secret management, ruleset modification, branch protection modification, or production connector activation.

## Mandatory Conditions
- Two approvals are present: `USBAY-AUDIT` and `USBAY-GLOBAL23`.
- Business justification exists.
- Policy reference exists.
- Risk assessment exists.
- Permission manifest exists.
- Repository scope exists.
- Installation scope exists.
- Rollback plan exists.
- Audit authority exists.
- Secret governance plan exists.
- Credential authority record exists.

## Authority Model
- Authorized creator: `USJAY77`, limited to creation after mandatory approvals and complete evidence.
- Approval authority: `USBAY-AUDIT` and `USBAY-GLOBAL23`.
- Review authority: `USBAY-AUDIT` and `USBAY-GLOBAL23`.
- Revocation authority: `USBAY-AUDIT`, `USBAY-GLOBAL23`, and emergency `USJAY77`.
- Emergency authority: `USJAY77`, limited to blocking, disabling, or revocation. Emergency authority cannot approve production activation.
- Audit authority: `USBAY-AUDIT`.

## Mandatory Evidence
- Business justification.
- Policy reference.
- Risk assessment.
- Permission manifest.
- Repository scope.
- Installation scope.
- Rollback plan.
- Approval record.
- Audit authority record.
- Secret governance plan.
- Credential authority record.

## Mandatory Approvals
- `USBAY-AUDIT`
- `USBAY-GLOBAL23`

Approvals expire after 14 days or immediately after scope change, permission change, repository scope change, credential incident, or policy revision.

## Fail-Closed Blocking Conditions
- Approval missing.
- Minimum approvals not met.
- Policy reference missing.
- Permission manifest missing.
- Audit authority missing.
- Rollback plan missing.
- Risk assessment missing.
- Business justification missing.
- Repository scope missing.
- Installation scope missing.
- Secret governance plan missing.
- Credential authority missing.
- Approval expired.
- Approval revoked.
- Scope changed after approval.
- Raw secret detected.
- Self-approval detected.

## Production Activation Boundary
GitHub App creation must not automatically authorize:

- Repository mutations.
- Branch deletion.
- Pull request merge.
- Release creation.
- Secret management.
- Ruleset modification.
- Branch protection modification.

Activation requires a separate production readiness approval with credential storage evidence, permission validation evidence, approval workflow evidence, pre-action audit evidence, post-action receipt capture evidence, fail-closed negative test evidence, and production readiness review approval.

## Generated PR Body
## PURPOSE
PB-045 defines the governance authority required before any GitHub App may be created for USBAY.

## RISK
GitHub App creation can establish future automation authority over repositories. If creation authority, approvals, evidence, secret governance, and activation boundaries are unclear, USBAY could create a path to ungoverned repository mutation.

## POLICY LINK
AGENTS.md fail-closed, audit-first engineering, human oversight, branch governance, network governance, and secret/data hygiene rules. PB-042 GitHub production connector design, PB-043 onboarding plan, and PB-044 onboarding readiness execution.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 approvals are mandatory before GitHub App creation. Creation does not authorize production activation, credentials, API calls, or repository mutation.

## GOVERNANCE CHECKS
JSON evidence must parse. Authority model must define creator, approval, review, revocation, emergency, and audit authority. Required approvals, creation evidence, credential authority, secret governance, fail-closed conditions, production activation boundary, metadata, and required PR sections must be present.

## AUDIT
PB-045 generates governance/evidence/pb045/github_app_creation_authority.json and governance/evidence/pb045/github_app_creation_authority_summary.md with authority assignments, approval evidence requirements, credential authority, secret governance, fail-closed conditions, and activation boundaries.

## IMPACT
USBAY can approve GitHub App creation only under strict controls while preserving fail-closed separation between app creation and production connector activation.

## Decision
VERIFIED

## Status
READY_FOR_REVIEW
