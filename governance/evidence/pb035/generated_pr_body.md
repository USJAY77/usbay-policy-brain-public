## PURPOSE
PB-035 resolves the branch policy drift proven by PB-034 by aligning PB release branch generation with the existing governed branch hygiene allow-list.

## RISK
If branch generation and branch hygiene remain misaligned, valid USBAY PB branches can be refused after successful merge and approved cleanup. If the remediation widens branch hygiene too broadly, unauthorized branch namespaces could become deletion-eligible.

## POLICY LINK
AGENTS.md branch governance and fail-closed rules. PB-034 evidence: governance/evidence/pb034/allowed_branch_policy_audit.json. PB-035 evidence: governance/evidence/pb035/branch_policy_alignment_report.json.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 review are required before merge. No admin bypass, auto-approval, or branch protection bypass is permitted.

## GOVERNANCE CHECKS
Focused validation must prove generated PB release branches use governance/*, valid governance/* PB branches pass branch hygiene, invalid branch prefixes fail closed, and branch_pattern_not_allowed remains enforced.

## AUDIT
PB-035 records the option comparison, selected remediation, files changed, test evidence, and fail-closed behavior in governance/evidence/pb035/branch_policy_alignment_report.json.

## IMPACT
PB release automation now emits governance/<pb_slug> branches. The branch hygiene allow-list remains unchanged, so arbitrary usbay/* branches are not made deletion-eligible.

## Decision
VERIFIED

## Status
READY FOR REVIEW
