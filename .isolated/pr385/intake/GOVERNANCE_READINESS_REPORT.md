# USBAY Intake Gateway Governance Readiness Report

## Scope

This report covers the USBAY Intake Gateway MVP routes:

- `/intake`
- `/intake/api`
- `/intake/audit`
- `/intake/admin`
- `/intake/retention`
- `/intake/email-policy`
- `/intake/readiness`

## Current Readiness Position

Status: `PRODUCTION READINESS PHASE 2 IMPLEMENTED FOR CONTROLLED REVIEW`

The intake gateway is not claimed as production-ready for unrestricted public deployment. Phase 2 adds fail-closed readiness evidence, admin access audit events, and admin key-rotation validation on top of the Phase 1 control layer, subject to human review and full-suite validation.

## Completed Controls

Forbidden runtime artifact removal:

- Removed `secrets/.DS_Store`.
- Existing `.gitignore` already blocks `.DS_Store` and `secrets/`.

Fail-closed validation:

- Missing required fields block submission.
- Invalid email blocks submission.
- Invalid boolean control fields block submission.
- Missing fail-closed requirement blocks submission.
- Persistence failure blocks submission.
- Ungoverned email transport blocks submission.
- Rate limit exhaustion blocks submission.

Storage:

- Submissions are stored in SQLite with full synchronous writes and WAL journaling.
- Notification outbox records are stored in SQLite.
- Intake audit evidence is stored in WORM-style append-only hash-chained JSONL.

Audit:

- Audit records include actor, device, decision, timestamp, and policy version.
- Raw contact email and organization values are hashed in the audit log.
- Audit chain export verifies previous/current hash continuity.

Admin access:

- `/intake/audit`, `/intake/admin`, `/intake/retention`, and `/intake/email-policy` require `x-usbay-admin-token`.
- Missing admin token fails closed.
- Scoped roles are enforced through the admin identity model.
- Revoked admin identities are blocked.
- Key rotation metadata is part of the admin identity policy.
- Phase 2 readiness requires at least one active scoped admin identity with current key rotation evidence.
- Protected admin exports append hash-only admin access events to the WORM audit chain.

Retention:

- Default retention is 365 days.
- Each submission includes `retention_until_epoch`.
- Retention policy export is available to authenticated administrators.
- Deletion mode is manual review required.

Rate limiting:

- Public intake submissions are rate-limited through Redis-backed distributed counters.
- Client identifiers are hash-only.
- Default limit is 5 requests per 3600 seconds.
- Redis unavailability blocks public intake submissions.

Email policy:

- Network delivery is disabled until a governed transport is approved.
- Notification is queued to a governed durable outbox for `governance@usbay.global`, `pilot@usbay.global`, and `audit@usbay.global`.
- Any non-approved email transport fails closed.

Phase 2 readiness:

- `/intake/readiness` is authenticated and scoped to `intake:policy`.
- Readiness verifies SQLite durable datastore access and schema metadata.
- Readiness verifies WORM hash-chain continuity.
- Readiness verifies Redis-backed rate-limit backend availability.
- Readiness verifies governed outbox recipients and blocks unapproved external delivery.
- Readiness verifies admin identity rotation evidence.
- Readiness verifies retention policy and manual-review deletion mode.
- Any failed readiness check returns `BLOCKED` and HTTP 503.

## Remaining Gaps

Email delivery:

- External email transport is not enabled.
- A governed email provider, credential handling, retry policy, delivery audit, and failure semantics are required before network delivery.

Abuse controls:

- Redis-backed distributed rate limiting is implemented.
- Production deployment still requires Redis availability monitoring and capacity policy.

Admin access:

- Scoped admin identity is implemented.
- Enterprise deployment should integrate with the organization's governed identity provider.
- Current local identity policy is suitable for controlled review only, not final enterprise SSO deployment.

Retention enforcement:

- Retention metadata exists.
- Automated deletion is intentionally not enabled because deletion requires manual governance review.

## Validation Evidence

Passing targeted tests:

- `tests/test_deployment_provenance.py`
- `tests/test_live_pilot_v1.py`
- `tests/test_intake_gateway.py`

Additional gateway regression validation:

- `tests/test_gateway_app.py`

Phase 2 validation expectations:

- Phase 2 readiness passes only with durable storage, valid WORM chain, Redis availability, governed outbox policy, active rotated admin identity, and retention policy.
- Phase 2 readiness fails closed if Redis is unavailable.
- Phase 2 readiness fails closed if admin rotation evidence is missing.
- Phase 2 readiness fails closed if WORM audit evidence is tampered.

## Production Readiness Estimate

Estimated status: `CONTROLLED PHASE 2 REVIEW READY AFTER HUMAN REVIEW`

Not yet production-ready for unrestricted external traffic until:

- durable storage is approved
- governed email delivery is approved
- external email transport is approved
- Redis availability monitoring is deployed
- admin authentication is integrated with governed enterprise identity
- full repository test suite completes cleanly
