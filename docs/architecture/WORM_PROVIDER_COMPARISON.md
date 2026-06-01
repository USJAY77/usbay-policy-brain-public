# WORM Provider Comparison

Purpose: compare external WORM pilot candidates using repository evidence only.

Runtime impact: none.

Certification impact: none. This comparison does not approve a provider and does not close BLOCKER-003.

Evidence rule: no provider claims without repository evidence.

## Provider Comparison

| Provider | Object lock | Legal hold | Retention enforcement | Auditability | Export verification | Governance suitability |
|---|---|---|---|---|---|---|
| AWS S3 Object Lock | Information not provided. | Information not provided. | Information not provided. | Information not provided. | Information not provided. | PILOT CANDIDATE ONLY: no repository evidence proves provider suitability. |
| Azure Immutable Blob Storage | Information not provided. | Information not provided. | Information not provided. | Information not provided. | Information not provided. | PILOT CANDIDATE ONLY: no repository evidence proves provider suitability. |
| Google Cloud Bucket Lock | Information not provided. | Information not provided. | Information not provided. | Information not provided. | Information not provided. | PILOT CANDIDATE ONLY: no repository evidence proves provider suitability. |

## Required Provider Evidence Before Suitability Decision

Each provider must provide:

- Immutable write proof.
- Provider object ID.
- Provider storage location identifier.
- Provider receipt timestamp.
- SHA256 object hash.
- Retention class.
- Retention-until timestamp.
- Legal hold state.
- Delete denial evidence.
- Overwrite denial evidence.
- Provider audit reference.
- Export verification record.
- Failure-mode evidence for outage, missing receipt, hash mismatch, missing retention, and missing legal hold.

## Governance Decision

Current provider approval status:

Decision: BLOCKED.

Reason: no provider-specific repository evidence exists.

Allowed next step:

Decision: PILOT.

The pilot may collect provider evidence. It must not certify or deploy external WORM storage.
