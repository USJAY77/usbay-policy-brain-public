## PURPOSE
PB-036 validates that the PB-035 branch policy remediation works by generating a governed release branch and running branch hygiene against that branch.

## RISK
If PB release automation still generates a disallowed branch namespace, successful post-merge cleanup can be refused and audit comments can report a false governance failure.

## POLICY LINK
AGENTS.md branch governance, fail-closed behavior, and audit-first engineering. PB-035 remediation evidence: governance/evidence/pb035/branch_policy_alignment_report.json. PB-036 validation evidence: governance/evidence/pb036/release_automation_validation.json.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 review are required before merge. No admin merge, auto-approval, or branch protection bypass is permitted.

## GOVERNANCE CHECKS
Validation must prove that governance/release-automation-validation is generated, branch_pattern_not_allowed is absent, delete_branch remains eligible, governance checks pass, and comment_refusal() is not invoked.

## AUDIT
PB-036 records generated release metadata, branch hygiene input, direct branch hygiene output, main-path validation output, and acceptance flags in governance/evidence/pb036/release_automation_validation.json.

## IMPACT
PB-036 demonstrates that valid governance/* PB release branches complete branch hygiene without producing a governed post-merge refusal path.

## Decision
VERIFIED

## Status
READY FOR REVIEW
