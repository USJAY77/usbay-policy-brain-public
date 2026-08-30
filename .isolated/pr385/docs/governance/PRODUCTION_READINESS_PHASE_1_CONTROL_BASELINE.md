# Production Readiness Phase 1 Control Baseline

This Phase 1 baseline defines a local, deterministic production-readiness gate
for USBAY as an execution control layer. It does not deploy, activate
production, call providers, open sockets, submit regulator exports, or perform
external signing.

## Architecture

The baseline has three local artifacts:

- A machine-readable manifest at
  `governance/evidence/production_readiness_phase1_manifest.json`.
- A deterministic evaluator in `governance.production_readiness_baseline`.
- Focused tests in `tests/test_production_readiness_baseline.py`.

The evaluator reads the manifest, validates every mandatory control, verifies
that referenced evidence files exist, hashes those references, and returns a
deterministic readiness result. Missing, malformed, unknown, duplicated, failed,
or blocked controls return `BLOCKED`.

## Control Definitions

Phase 1 requires these controls:

- PR-001 Production readiness manifest valid
- PR-002 Fail-closed release gate active
- PR-003 Security baseline documented
- PR-004 Secrets handling contract present
- PR-005 Monitoring contract present
- PR-006 Alerting contract present
- PR-007 Backup contract present
- PR-008 Restore validation contract present
- PR-009 Incident response contract present
- PR-010 Rollback contract present
- PR-011 Human release approval required
- PR-012 Audit evidence export available
- PR-013 Dependency integrity validation available
- PR-014 Runtime reconciliation available
- PR-015 Production activation remains disabled by default

## Fail-Closed Behavior

Readiness evaluation may report `READY` only when every required control is
present, complete, evidence-backed, and blocker-free. Release readiness remains
`BLOCKED` until an explicit human approval is bound to the exact commit SHA,
readiness evaluation ID, policy version, and non-expired approval timestamp.

## Evidence Model

Evidence export is hash-only and redacted. The export includes control results,
overall readiness state, blockers, referenced evidence hashes, policy version,
evaluator version, timestamp, and human approval state. It never serializes raw
payloads, credentials, approval contents, private keys, or provider receipts.

## Human Approval Boundary

Human approval is external metadata. A valid approval must include the Phase 1
approval schema, `APPROVED` state, exact commit SHA, exact readiness evaluation
ID, exact policy version, expiration timestamp, and a deterministic approval
hash. Stale, mismatched, malformed, or missing approval blocks release.

## Rollback Procedure

Rollback is isolated to this additive baseline:

1. Revert `governance/production_readiness_baseline.py`.
2. Revert `governance/evidence/production_readiness_phase1_manifest.json`.
3. Revert `tests/test_production_readiness_baseline.py`.
4. Revert this document.

No runtime execution path, provider adapter, deployment configuration, policy
engine, or workflow must be changed for rollback.

## Limitations

Phase 1 proves local baseline readiness controls only. It does not provide live
WORM storage, RFC3161 timestamp authority integration, external signing,
provider activation, object-lock persistence, regulator submission, deployment,
or production activation.

## Phase 2 Dependencies

Phase 2 should add provider-neutral validation for controlled production
evidence intake, live monitoring evidence receipts, backup and restore execution
proofs, and human governance review records while preserving fail-closed release
blocking.
