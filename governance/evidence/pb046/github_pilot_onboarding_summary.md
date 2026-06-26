# PB-046 GitHub Pilot Onboarding Package

## Decision
PACKAGE_COMPLETE

## Status
READY_FOR_REVIEW

## Evidence Boundary
This PB creates onboarding package templates only. It does not create a GitHub App, create credentials, call APIs, mutate repositories, or activate production.

## Is Every Required Onboarding Artifact Defined?
Yes. The package defines all eight requested onboarding artifact templates:

- `business_justification.json`
- `risk_assessment.json`
- `permission_manifest.json`
- `repository_scope.json`
- `installation_scope.json`
- `rollback_plan.json`
- `audit_authority_record.json`
- `credential_authority_record.json`

## Is The Package Complete?
Yes as a template package.

No as live onboarding evidence. GitHub App creation remains blocked until every template is populated with real evidence, approved by `USBAY-AUDIT` and `USBAY-GLOBAL23`, and linked to an audit record.

## Required Approval References
- `USBAY-AUDIT`
- `USBAY-GLOBAL23`

## Validation Rules
- All eight templates must exist in the package definition.
- Every template must define purpose, required fields, validation rules, and fail-closed checks.
- Approval references must include `USBAY-AUDIT` and `USBAY-GLOBAL23` where required.
- No template may permit raw credential storage in repository evidence.
- No template may authorize production activation.
- Any missing required field in a populated onboarding artifact blocks GitHub App creation.

## Fail-Closed Checks
- Template missing.
- Required field missing.
- Approval reference missing.
- Validation rule missing.
- Fail-closed check missing.
- Raw secret allowed.
- Production activation implied.
- Repository mutation implied.

## Evidence Still Missing Before First GitHub App Creation
- Populated business justification.
- Populated risk assessment.
- Populated permission manifest.
- Populated repository scope.
- Populated installation scope.
- Populated rollback plan.
- Populated audit authority record accepted by `USBAY-AUDIT`.
- Populated credential authority record.
- Approval records from `USBAY-AUDIT` and `USBAY-GLOBAL23`.
- Audit record linking all package artifacts.

## Generated PR Body
## PURPOSE
PB-046 creates the template package required before the first USBAY GitHub App may be created.

## RISK
If onboarding artifacts are incomplete or ambiguous, USBAY could create a GitHub App without business justification, risk review, permission boundaries, repository scope, rollback, audit authority, credential authority, or required approvals.

## POLICY LINK
AGENTS.md fail-closed, audit-first engineering, human oversight, branch governance, network governance, and secret/data hygiene rules. PB-045 GitHub App Creation Authority.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 must approve populated onboarding evidence before any GitHub App creation. This PB does not create the app, credentials, API calls, mutations, or production activation.

## GOVERNANCE CHECKS
JSON evidence must parse. All eight templates must define required fields, validation rules, fail-closed checks, and approval references where required. Diff hygiene and conflict marker scan must pass.

## AUDIT
PB-046 generates governance/evidence/pb046/github_pilot_onboarding_package.json and governance/evidence/pb046/github_pilot_onboarding_summary.md with template definitions, validation rules, fail-closed checks, approval references, and missing evidence before creation.

## IMPACT
USBAY gains a complete onboarding package structure while keeping first GitHub App creation blocked until the templates are populated, approved, and audit-linked.

## Decision
VERIFIED

## Status
READY_FOR_REVIEW
