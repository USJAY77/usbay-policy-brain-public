# USBAY Governance PR Fallback Guard

## PURPOSE
This fallback template is not an approval artifact. Governance PRs must use a generated PB PR body from the governed metadata/template authority before review.

## RISK
If this fallback body appears on a governance PR, the PR must be treated as `REVIEW_REQUIRED` until replaced with the generated governance body.

## POLICY LINK
AGENTS.md fail-closed branch governance, human oversight, and audit-first engineering requirements.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Generated governance PR body attached
- Required sections populated
- No unresolved placeholders present
- Branch protection preserved
- No admin merge or auto-approval

## AUDIT
Fallback template use is not sufficient audit evidence. Generated PR body evidence must be attached before merge.

## IMPACT
The fallback guard prevents unresolved template placeholders from entering governance review while preserving fail-closed handling for non-generated PR bodies.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL
