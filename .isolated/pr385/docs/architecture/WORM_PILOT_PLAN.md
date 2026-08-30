# External WORM Pilot Plan

Purpose: define a governed pilot for external WORM evidence preservation without deploying infrastructure, connecting cloud providers, or modifying runtime enforcement.

Runtime impact: none.

Certification impact: none. This plan does not close BLOCKER-003.

Decision: PILOT.

Evidence rule: repository evidence only. Do not fabricate provider capabilities, provider receipts, retention proof, legal hold proof, audit receipts, export verification, or certification status.

## Pilot Scope

The pilot evaluates whether external immutable storage can preserve USBAY governance evidence with regulator-grade auditability.

In scope:

- External WORM evidence preservation design.
- Provider evidence requirements.
- Provider receipt model.
- Retention and legal hold verification requirements.
- Export verification requirements.
- Failure-mode requirements.
- Documentation required to evaluate AWS S3 Object Lock, Azure Immutable Blob Storage, and Google Cloud Bucket Lock.

Out of scope:

- Production enforcement changes.
- Runtime policy changes.
- Cloud account creation.
- Bucket/container creation.
- Provider API integration.
- Provider credential handling.
- Certification claims.
- Infrastructure deployment.

## Pilot Objectives

1. Prove whether an external provider can preserve USBAY evidence as immutable, hash-verifiable, audit-receipted records.
2. Preserve the existing local WORM readiness boundary until provider evidence is verified.
3. Define the minimum evidence required to update BLOCKER-003 from OPEN to PARTIAL or CLOSED.
4. Preserve fail-closed behavior when provider evidence is missing or unverifiable.
5. Ensure regulator export profiles can bind provider evidence without exposing raw payloads, approval contents, private keys, secrets, or raw regulator exports.

## Success Criteria

The pilot passes only if all of the following evidence exists:

- Provider write receipt captured.
- Provider object ID captured.
- Provider storage location identifier captured.
- SHA256 evidence hash matches USBAY evidence hash.
- Retention class captured.
- Retention-until timestamp captured.
- Legal hold state captured.
- Immutable write proof captured.
- Provider audit receipt captured.
- Export verification record captured.
- Delete attempt denied during retention.
- Overwrite attempt denied.
- Provider outage fails closed.
- Missing receipt fails closed.
- Missing retention proof fails closed.
- Missing legal hold proof fails closed.
- Diagnostics remain hash-only and redacted.

## Failure Criteria

The pilot fails if any of the following occurs:

- Provider receipt is missing.
- Object ID is missing.
- Retention class is missing.
- Legal hold state is missing.
- Immutable write proof is missing.
- Audit receipt is missing.
- Export verification record is missing.
- SHA256 evidence hash mismatches.
- Delete succeeds during retention.
- Overwrite succeeds.
- Provider outage produces an allow or verified state.
- Provider evidence cannot be bound to USBAY sealed archive and WORM readiness identifiers.
- Raw payloads, approval contents, private keys, secrets, raw nonces, or raw regulator exports appear in evidence or diagnostics.

Failure outcome:

Decision: BLOCKED.

## Governance Controls

- Provider evidence must be captured before any certification claim.
- Human approval is not evidence.
- Missing provider proof blocks certification.
- Provider receipts must be hash-bound to USBAY evidence identifiers.
- Export verification must fail closed on missing provider evidence.
- Provider selection must be documented before implementation.
- Each provider pilot must be isolated from production runtime enforcement.
- One external WORM provider implementation must be scoped to one governance capability branch.

## Audit Requirements

The pilot audit record must include:

- Pilot provider name.
- Pilot date.
- USBAY sealed archive ID.
- USBAY archive root hash.
- USBAY WORM storage plan ID.
- Provider receipt.
- Provider object ID.
- SHA256 evidence hash.
- Retention class.
- Retention-until timestamp.
- Legal hold state.
- Immutable write proof.
- Provider audit reference.
- Export verification result.
- Failure-mode test results.
- Redaction verification result.

If any audit requirement is missing:

Decision: BLOCKED.
