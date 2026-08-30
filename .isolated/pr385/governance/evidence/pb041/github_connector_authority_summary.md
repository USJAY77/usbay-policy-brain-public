# PB-041 GitHub Connector Authority Summary

## Decision
PARTIAL

## Status
READY_FOR_REVIEW

## Assessment Boundary
This PB is governance-definition only. No live GitHub mutations were performed. No production credentials were created, stored, or tested. No external GitHub API calls were made.

## Can GitHub Become The First Production-Governed Connector?
Yes, GitHub is the best first candidate, but it remains `PARTIAL` until production credential authority and a governed live connector implementation exist.

## Already Satisfied
- Connector defined.
- Policy gate defined.
- Permission model defined.
- Approval gate modeled.
- Fail-closed support modeled.
- Audit output defined.
- Dry-run supported.
- Sensitive data redaction supported.

## Missing Controls
- Production GitHub App or fine-grained token credential evidence.
- Production connector implementation.
- Credential storage reference.
- Credential rotation evidence.
- Repository-scoped authority evidence.
- Live GitHub permission validation evidence.
- Pre-mutation audit write implementation.
- Post-action GitHub audit receipt capture.

## Minimum Production Onboarding Checklist
1. Create repository-scoped GitHub App installation or fine-grained token with least privilege.
2. Store credential outside repository in an approved secret manager or protected GitHub environment secret.
3. Record credential authority owner, scope, expiration, and rotation plan.
4. Implement production connector behind the PB-038 policy gate.
5. Map every enabled capability to the PB-041 permission matrix.
6. Require human approval for branch, PR, merge, release, ruleset, branch protection, and secret actions.
7. Write audit record before every mutation.
8. Capture GitHub response receipt after every successful mutation.
9. Fail closed on GitHub API failure, audit write failure, permission mismatch, or missing approval.
10. Validate with a non-destructive pilot capability before enabling broader production actions.

## Final Decision
PARTIAL
