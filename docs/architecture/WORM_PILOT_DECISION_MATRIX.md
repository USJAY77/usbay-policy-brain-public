# WORM Pilot Decision Matrix

Purpose: define governed decision outcomes for external WORM pilot readiness.

Runtime impact: none.

Certification impact: none. This matrix does not close BLOCKER-003.

## Decision Outcomes

| Decision | Governance criteria | Allowed action | Certification impact |
|---|---|---|---|
| DEFER | Provider evidence cannot be collected; provider suitability cannot be evaluated; cost, access, or governance owner is missing. | Do not run pilot. Keep local-only WORM readiness. | BLOCKER-003 remains OPEN. |
| PILOT | Provider candidate selected for evidence collection; no infrastructure is deployed by this document; evidence requirements are defined; production runtime remains unchanged. | Run a governed, isolated evidence-collection pilot after separate authorization. | BLOCKER-003 remains OPEN until evidence is collected and verified. |
| IMPLEMENT | Provider evidence is complete; immutable write proof, retention proof, legal hold proof, audit receipt, export verification, failure-mode evidence, and redaction verification all pass. | Create a separate implementation plan and one-capability branch for provider integration. | BLOCKER-003 may move only after certification evidence is reviewed and recorded. |

## Minimum Criteria For PILOT

- Pilot owner documented.
- Provider candidate documented.
- Evidence requirements documented.
- Failure-mode tests documented.
- No production enforcement modification.
- No provider claims without evidence.
- No certification claims.
- Human approval not used as evidence.

## Minimum Criteria For IMPLEMENT

Implementation is blocked until all are true:

- Provider write receipt captured.
- Provider object ID captured.
- Retention verified.
- Legal hold verified.
- Immutable write proof captured.
- Delete attempt denied.
- Overwrite attempt denied.
- Export verification succeeds.
- Provider outage fails closed.
- Redaction verification passes.
- BLOCKER-003 evidence requirements are updated.

If any criterion is missing:

Decision: BLOCKED.

## Current Decision

Decision: PILOT.

Reason: repository evidence shows local WORM readiness and fail-closed planning, but no external provider evidence.
