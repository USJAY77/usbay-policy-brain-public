# USBAY Intake Gateway MVP

## Routes

`/intake`

Static governance assessment request page.

`/intake/api`

JSON API for creating governance assessment requests.

`/intake/audit`

Authenticated hash-chained audit export for intake submissions.

`/intake/admin`

Authenticated intake administration export containing submissions, notification records, audit status, retention policy, and email delivery policy.

`/intake/retention`

Authenticated retention policy export.

`/intake/email-policy`

Authenticated governed email delivery policy export.

`/intake/readiness`

Authenticated Phase 2 production readiness evidence. This route fails closed unless durable storage, WORM audit, Redis-backed rate limiting, governed outbox policy, active rotated admin identity, and retention policy checks all pass.

## Required API Fields

The intake API requires:

- `organization`
- `contact_name`
- `contact_email`
- `role`
- `governance_scope`
- `policy_validation_required`
- `human_oversight_required`
- `audit_evidence_required`
- `provenance_required`
- `fail_closed_required`

Optional risk context:

- `regulated_industry`
- `high_risk_ai`
- `target_timeline`

Accepted roles:

- `CISO`
- `Compliance Officer`
- `AI Governance Lead`
- `Enterprise Risk Manager`
- `Internal Audit`
- `Legal`
- `Security Engineering`
- `Other`

## Fail-Closed Behavior

The request is blocked when:

- a required field is missing
- an email address is invalid
- a boolean control field is malformed
- fail-closed enforcement is not explicitly required
- the submission cannot be stored
- the notification record cannot be queued
- the audit record cannot be appended
- the audit chain is invalid
- the public intake rate limit is exceeded
- the governed email delivery policy is invalid
- admin credentials are missing from protected routes
- admin key rotation evidence is missing from Phase 2 readiness
- Redis-backed distributed rate limiting is unavailable during Phase 2 readiness
- WORM audit chain verification fails during protected export or readiness checks

Blocked requests return `decision: BLOCKED`.

## Storage

Default local storage directory:

`intake/storage`

Files:

- `intake.db`
- `audit.worm.jsonl`
- `retention.json`
- `email_delivery_policy.json`
- `admin_identity_policy.json`

Override storage location:

`USBAY_INTAKE_STORAGE_DIR=/path/to/storage`

## Notification

The MVP does not make external network calls. Notification is queued to a governed durable outbox for:

`governance@usbay.global`

`pilot@usbay.global`

`audit@usbay.global`

The notification record includes:

- recipient
- submission ID
- submission hash
- risk classification
- policy version
- delivery policy hash
- notification hash

Governed email delivery policy:

- default transport: `GOVERNED_OUTBOX`
- network delivery: disabled
- recipients: `governance@usbay.global`, `pilot@usbay.global`, `audit@usbay.global`
- ungoverned transports fail closed

`USBAY_INTAKE_EMAIL_TRANSPORT` must remain `GOVERNED_OUTBOX` until a governed provider, credentials handling, delivery audit, retry policy, and failure policy are approved.

## Admin Authentication

Protected routes require `x-usbay-admin-token`.

Configure one of:

- `USBAY_INTAKE_ADMIN_TOKEN`
- `USBAY_INTAKE_ADMIN_TOKEN_SHA256`

If no admin token is configured, admin and audit routes fail closed.

Phase 1 admin identity model:

- scoped roles: `intake_admin`, `intake_auditor`, `intake_operator`
- required scopes: `intake:read`, `intake:audit`, `intake:policy`
- revoked identities are blocked
- key rotation metadata is required in the admin identity policy

Phase 2 readiness requires at least one active admin identity with:

- scoped role
- key version
- token hash
- future `rotates_after_epoch`

Protected admin exports append hash-only admin access events to the WORM audit chain before returning sensitive evidence.

## Retention

Default retention period:

`365 days`

Override:

`USBAY_INTAKE_RETENTION_DAYS=365`

Retention metadata is recorded on each submission as `retention_until_epoch`.

Deletion mode is manual review required. The MVP does not automatically delete governance evidence.

## Rate Limiting

Default rate limit:

- `5` requests
- `3600` seconds

Overrides:

- `USBAY_INTAKE_RATE_LIMIT_MAX_REQUESTS`
- `USBAY_INTAKE_RATE_LIMIT_WINDOW_SECONDS`

Rate limiting uses hash-only client identifiers and Redis-backed distributed counters.

If Redis is unavailable or not configured, public intake submission fails closed.

## Audit

The audit log is WORM-backed append-only JSONL with chained hashes. Audit records include:

- actor
- device
- decision
- timestamp
- policy version
- submission hash
- contact email hash
- organization hash
- risk level
- notification hash
- previous hash
- audit hash

Raw submission content is not duplicated in the audit log.

Admin access audit records include:

- actor
- device
- decision
- timestamp
- policy version
- admin action
- admin identity hash
- key version
- role
- rotation state

Admin tokens are never written to audit evidence.

## Phase 2 Readiness

`/intake/readiness` returns `READY_FOR_CONTROLLED_PHASE2_REVIEW` only when all readiness checks pass:

- SQLite durable datastore schema check
- WORM audit hash-chain verification
- Redis-backed distributed rate-limit availability check
- governed outbox email policy check
- active admin identity with current key rotation evidence
- retention policy check

Readiness does not enable external email delivery and does not claim unrestricted production readiness. External network delivery remains blocked pending governed provider approval and human review.

## Risk Classification

Risk is classified from the submitted control context:

- regulated industry
- high-risk AI workflow
- human oversight requirement
- policy validation requirement
- audit evidence requirement
- provenance requirement
- fail-closed requirement

Risk levels:

- `LOW`
- `MEDIUM`
- `HIGH`

## Example Request

```json
{
  "organization": "Example Enterprise",
  "contact_name": "Governance Owner",
  "contact_email": "governance.owner@example.com",
  "role": "AI Governance Lead",
  "governance_scope": "Assessment of AI-assisted workflow controls before enterprise deployment.",
  "regulated_industry": true,
  "high_risk_ai": true,
  "policy_validation_required": true,
  "human_oversight_required": true,
  "audit_evidence_required": true,
  "provenance_required": true,
  "fail_closed_required": true,
  "target_timeline": "30-60 days"
}
```
