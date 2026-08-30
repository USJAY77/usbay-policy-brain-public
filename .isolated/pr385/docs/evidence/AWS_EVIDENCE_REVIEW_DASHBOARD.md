# AWS Evidence Review Dashboard

Purpose: document the local read-only governance dashboard for AWS Object Lock provider evidence readiness.

Runtime impact: none.

Gateway impact: none.

Policy enforcement impact: none.

AWS resource creation: none.

Provider credentials stored in repository: prohibited.

Certification claim: prohibited.

BLOCKER-003 = OPEN.

Certification = BLOCKED.

## Dashboard Command

Run:

```text
python3 dashboard/evidence_review_dashboard.py
```

JSON output:

```text
python3 dashboard/evidence_review_dashboard.py --format json
```

Pilot submission output:

```text
python3 dashboard/evidence_review_dashboard.py --evidence-dir governance/evidence/aws-object-lock/pilot-submission
```

## Evidence Inventory

The dashboard shows:

- Required evidence list.
- Received evidence list.
- Missing evidence list.
- Placeholder evidence list.
- Rejected evidence list.

Required evidence:

- Object Lock write receipt.
- Retention configuration evidence.
- Legal hold evidence.
- Export verification record.
- Provider audit reference.
- Chain-of-custody record.
- Evidence manifest.

## Validation View

The dashboard shows:

- Validation status.
- Hash verification status.
- Manifest status.
- Chain-of-custody status.

Validation remains `BLOCKED` while required evidence is missing, placeholder-only, rejected, hash-mismatched, or review-incomplete.

## Review View

The dashboard shows:

- Reviewer assignments.
- Review status.
- Approval status.
- Rejection status.

Reviewer approval is not evidence.

Review status remains `BLOCKED` until complete evidence is validated and reviewed.

## Governance View

The dashboard shows:

- BLOCKER-001 status.
- BLOCKER-002 status.
- BLOCKER-003 status.
- Certification status.

Current governance state:

- BLOCKER-001 = CLOSED.
- BLOCKER-002 = PARTIAL.
- BLOCKER-003 = OPEN.
- Certification = BLOCKED.

## Dashboard Logic

If required evidence is missing:

BLOCKER-003 = OPEN.

If validation fails:

BLOCKER-003 = OPEN.

If review is incomplete:

BLOCKER-003 = OPEN.

Certification must remain BLOCKED unless human governance review explicitly changes status with evidence.

## Fail-Closed Boundary

The dashboard is read-only.

The dashboard does not create AWS resources.

The dashboard does not store credentials.

The dashboard does not verify AWS.

The dashboard does not certify immutable storage.

The dashboard does not close BLOCKER-003.

Only complete, validated, reviewed, audit-bound provider evidence may support a future BLOCKER-003 reassessment.
