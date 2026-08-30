# Audit Lineage Relationships

Purpose: define normalized relationships between policy decisions, evidence packages, validation results, review outcomes, export bundles, and future certification assessments.

Runtime impact: none.

Certification claim: prohibited.

Default decision: BLOCKED.

## Required Relationship Chain

The lineage chain must link:

1. Policy decision to evidence package.
2. Evidence package to validation result.
3. Validation result to review outcome.
4. Review outcome to export bundle.
5. Export bundle to certification assessment.

If any relationship is missing:

Decision = BLOCKED.

## Decision Lineage Tracking

Policy decision lineage must record:

- Decision identifier.
- Decision source path.
- Decision hash.
- Decision actor when available.
- Decision timestamp when available.
- Bound evidence package identifier.

## Evidence Lineage Tracking

Evidence package lineage must record:

- Evidence package identifier.
- Evidence package path.
- Evidence package hash.
- Required artifact list.
- Missing artifact list.
- Bound validation result identifier.

## Validation Lineage Tracking

Validation lineage must record:

- Validation result identifier.
- Validation script path.
- Validation output hash.
- Validation decision.
- Bound review outcome identifier.

## Review Lineage Tracking

Review lineage must record:

- Review outcome identifier.
- Reviewer reference.
- Review decision.
- Review timestamp when available.
- Bound export bundle identifier.

## Export Bundle Lineage Tracking

Export bundle lineage must record:

- Export bundle identifier.
- Export bundle path.
- Export bundle hash.
- Bundle verification result.
- Bound certification assessment identifier.

## Certification Lineage Tracking

Certification assessment lineage must record:

- Certification assessment identifier.
- Certification status.
- Assessment source path.
- Assessment hash.
- Bound export bundle identifier.

This framework does not create certification claims.

## Missing-Link Detection

Missing-link detection must fail closed when:

- Any required relationship is absent.
- Any relationship is `Information not provided.`
- Any required hash is missing.
- Any referenced source path is missing.
- Any blocker or certification state is changed by lineage data.

Missing-link outcome:

Decision = BLOCKED.

## Tamper Detection

Tamper detection must compare recorded hashes to canonical lineage content and source evidence hashes.

If any hash is malformed, missing, or mismatched:

Decision = BLOCKED.

## Fail-Closed Verification

Lineage verification passes only when all required relationships exist, all referenced paths exist, required hashes are valid, and no certification or blocker status is changed by the lineage record.

Until then:

Decision = BLOCKED.
