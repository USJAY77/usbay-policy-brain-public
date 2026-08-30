## RISK
Manual PB metadata entry can create audit drift across branch names, commit titles, PR titles, PR bodies, decision, and status.

## MECHANISM
PB-023 VERIFIED: Governance Metadata Authority derives all governed release metadata from one PB metadata source and validates the generated outputs before release use.

## GAP
This control does not bypass branch protection, approve reviews, merge pull requests, or create external certification claims.

## AUDIT
Generated metadata records the PB number, slug, title, branch, commit title, PR title, PR body sections, decision, and status.

## IMPACT
Governance release metadata becomes deterministic and fail-closed when metadata is missing, malformed, mismatched, or manually overridden.

## Decision
VERIFIED

## Status
READY FOR REVIEW
