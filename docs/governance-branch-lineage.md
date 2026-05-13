# Governance Branch Lineage

## Legacy Branch

- Legacy branch: `governance/architecture-boundaries-phase1`
- Affected PR range: `#36` through `#51`
- Status: already merged into `main`

## Risk

The legacy branch carried a broad governance capability scope across multiple merged PRs. Reusing one branch lineage for many capabilities can reduce audit clarity because branch identity no longer maps cleanly to a single capability, review surface, and merge decision.

This is a lineage documentation risk only. It does not require, authorize, or recommend rewriting merged history.

## Forward Policy

USBAY governance changes must proceed forward-only.

Rules:

- No history rewrite.
- No branch reuse.
- No restored deleted governance branches.
- No rebasing or replaying merged governance history to reshape branch lineage.
- Use a one-capability, one-branch, one-PR workflow.

## Future Governance Branch Examples

- `governance/pq-runtime-verification`
- `governance/tsa-live-verification`
- `governance/worm-immutable-storage`
- `governance/regulator-export-profile`
- `governance/evidence-renewal-runtime`
- `governance/revocation-live-fetch`
- `governance/audit-witness-attestation`
- `governance/policy-runtime-consensus`

## Audit Position

The affected PR range remains accepted as merged into `main`. Future governance work must preserve auditability through deterministic, capability-scoped, forward-only branch lineage.
