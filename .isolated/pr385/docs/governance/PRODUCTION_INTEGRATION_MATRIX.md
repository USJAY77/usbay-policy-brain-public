# Production Integration Matrix

## Purpose

The production integration matrix records the deferred external integration points required before production activation. It is metadata only. It does not enable runtime execution, network access, live signing, RFC3161 calls, WORM provider writes, object-lock writes, or regulator submission.

## Deferred Integrations

| Order | Integration | Purpose | Current Placeholder | Required Interface |
| --- | --- | --- | --- | --- |
| 1 | RFC3161 timestamp authority | Submit deterministic message-imprint material to a governed timestamp authority. | local policy OID placeholder | Hash-only TSA request/response verifier with certificate, policy OID, revocation, and imprint checks. |
| 2 | Timestamp authority chain | Bind timestamp authority chain readiness to governance evidence. | not configured | Read-only authority-chain verifier using hash-only chain metadata. |
| 3 | External signing authority | Attach externally verifiable signatures to signed auditor bundles. | not configured | Detached signing envelope verifier with public-key fingerprint binding and no private-key logging. |
| 4 | WORM storage provider | Persist sealed audit archive references into governed immutable storage. | `LOCAL_ONLY` | Provider-neutral WORM write receipt verifier using hash-only object references. |
| 5 | Object-lock persistence | Verify retention, legal hold, and immutability metadata from storage-provider receipts. | `LOCAL_ONLY` | Object-lock receipt verifier with retention mode, retain-until timestamp, and legal-hold status. |
| 6 | Regulator submission | Submit regulator export bundles only after evidence, WORM, timestamp, and signing gates verify. | `LOCAL_ONLY` | Regulator submission adapter with dry-run proof, delivery receipt verification, and no raw payload export. |

## Blocking Risks

- Unverified TSA tokens or timestamp chronology drift.
- Authority duplication or chain schema mismatch.
- Private-key exposure or untrusted signer fingerprints.
- Mutable storage outputs, missing legal holds, or retention mismatches.
- Provider receipt spoofing, clock skew, or object version mismatch.
- Raw payload leakage, jurisdiction mismatch, or unverified delivery receipts.

## Safety Rules

Every matrix entry keeps these flags false:

- `execution_allowed`
- `provider_execution`
- `production_activation`
- `network_access`
- `live_signing`
- `worm_provider_enabled`
- `regulator_submission_enabled`

The matrix is hash-only, deterministic, and fail-closed. Any schema drift, order drift, duplicate integration, hash mismatch, unsafe marker, or execution-flag drift blocks verification.

## Non-Goals

This matrix does not implement external services. It does not replace existing RFC3161, WORM, regulator export, signed bundle, audit evidence, runtime ledger, reconciliation, attestation, or registry validators. It only centralizes the future production-integration boundary for review.
