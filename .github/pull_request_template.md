# USBAY Governance PR Fallback Guard

## PURPOSE
This fallback template is not an approval artifact. Governance PRs must use a generated PB PR body from the governed metadata/template authority before review.

## Narrow non-PB CI maintenance route
After adoption of `docs/non_pb_ci_maintenance_route.md`, eligible non-PB CI
maintenance may use `scripts/non_pb_ci_maintenance_body.py` without assigning
a PB number. This replaces only the PB-body format for that narrow scope;
it does not waive governance checks, dependency-policy evidence, branch
protection or the two required human reviews. The generated non-PB body
remains REVIEW_REQUIRED / AWAITING_APPROVAL. Classification alone is not approval.
Mixed, ambiguous or protected-semantic changes require PB routing or human
clarification. Existing PB metadata/title/commit rules remain unchanged.

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
