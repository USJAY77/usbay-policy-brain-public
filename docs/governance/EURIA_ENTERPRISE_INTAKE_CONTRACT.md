# EURIA Governed Enterprise Intake Contract v1

EURIA is an intake and orchestration boundary. It may collect minimum enterprise
pilot intake metadata, normalize a request for USBAY governance, and present
`BLOCKED`, `REVIEW_REQUIRED`, or `APPROVED_FOR_PILOT`.

EURIA does not receive execution, policy, approval, deployment, enforcement, or
production-readiness authority.

## Authority Boundary

- `EURIA_EXECUTION_AUTHORITY=false`
- `EURIA_POLICY_AUTHORITY=false`
- `EURIA_APPROVAL_AUTHORITY=false`
- `EURIA_DEPLOYMENT_AUTHORITY=false`

Any contract attempting to override those values is blocked.

## Approval Boundary

`APPROVED_FOR_PILOT` requires both:

- a request-bound, tenant-bound, environment-bound, policy-bound,
  non-expired, non-revoked, non-AI-generated human approval reference
- successful Policy Brain validation metadata

EURIA cannot generate `APPROVED_FOR_PILOT` directly.

## Evidence Boundary

Evidence is hash-only governance metadata:

- `request_id`
- `contract_version`
- `decision`
- `policy_reference`
- `human_approval_reference`
- `timestamp`
- `contract_hash`
- `decision_hash`

No secrets, credentials, raw customer payloads, or unnecessary personal data are
included.

## Enforcement Boundary

The contract can produce `ELIGIBLE_FOR_GATEWAY`, `REVIEW_REQUIRED`, or
`BLOCKED`. It does not execute anything. The Enforcement Gateway remains the
only enforcement surface.
