# Euria Demo Integration

Purpose: document the Euria analysis layer added to the USBAY Governance Evidence Demo while preserving USBAY as the only enforcement authority.

Runtime impact: demo rendering only.

Production deployment: none.

AWS resources: none.

Credentials committed: none.

Private keys committed: none.

Certification claim: none.

Blocker status change: none.

Default decision: BLOCKED.

## Demo Flow

1. User submits evidence package.
2. Euria analyzes evidence.
3. Euria reports missing evidence, unsupported claims, privacy risks, and confidence summary.
4. USBAY Policy Brain evaluates governance state.
5. USBAY outputs `APPROVED`, `HUMAN REVIEW`, or `BLOCKED`.
6. Human reviewer records a decision when approval is requested.
7. USBAY audit evidence is generated.

## Euria Analysis Layer

Euria may:

- Analyze evidence.
- Identify missing evidence.
- Identify unsupported claims.
- Identify privacy risks.
- Summarize confidence as evidence-bound or blocked.
- Recommend human review or blocked status.

Euria may never:

- Execute actions.
- Approve requests.
- Modify policy.
- Bypass human review.
- Alter audit records.
- Override USBAY enforcement.

## USBAY Enforcement Boundary

USBAY remains the only enforcement authority.

The demo separates:

- Euria Recommendation.
- USBAY Decision.
- Human Approval Status.
- Audit Record ID.
- Signature Status.
- Timestamp Status.

If any state is missing, invalid, unsupported, unreviewed, unsigned, untimestamped, or audit-incomplete, the demo must show:

```text
BLOCKED
```

## Human Review Boundary

Human review is required for approval.

Human review may not bypass:

- USBAY policy validation.
- Evidence completeness.
- Signature evidence.
- Timestamp evidence.
- Audit chain completeness.
- Privacy restrictions.
- Prompt injection handling.

## Blocked Scenarios

The demo blocks:

- Missing evidence.
- Prompt injection.
- Unsupported claims.
- Privacy violations.

## Approved Scenario

The demo may show approval only when:

- Evidence is complete.
- USBAY policy validation passes.
- Human approval is completed.
- Audit chain is complete.
- Signature status is present and valid.
- Timestamp status is present and valid.

The current default fixture remains fail-closed when reviewer evidence is incomplete.

## Component Files

The React-compatible presentation panels are:

- `frontend/components/EuriaAnalysisPanel.tsx`
- `frontend/components/USBAYDecisionPanel.tsx`
- `frontend/components/HumanReviewPanel.tsx`
- `frontend/components/AuditEvidencePanel.tsx`

The existing static demo renderer also renders equivalent panels in `demo/templates/governance_demo_flow.html`.
