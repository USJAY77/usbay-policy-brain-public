# Attestation And Export Bundle Persistence Registry

## Purpose

The attestation/export registry persists reconciliation attestations and regulator export bundles as local, append-only, hash-linked JSONL records. It is a governance persistence layer only. It does not authorize execution, sign data, submit exports, repair records, migrate history, or contact external services.

## Persistence Architecture

Two record types share one registry verifier:

- reconciliation attestation registry records
- regulator export bundle registry records

Each record stores hashes and references only. Registry entries bind to the previous registry hash and include a deterministic registry record hash.

## Acceptance Gates

Attestation records require:

- valid attestation;
- valid reconciliation result;
- existing audit record reference;
- existing runtime ledger record reference;
- tenant, policy version, evidence ID, decision, failure code, audit hash, ledger hash, and reconciliation report hash continuity.

Export records require:

- valid linked attestation registry record;
- valid export bundle manifest;
- matching tenant, policy version, evidence ID, audit reference, ledger reference, and attestation reference.

Anything else blocks.

## Append Lifecycle

The append path:

1. validates the existing registry;
2. checks the caller-provided expected previous hash;
3. builds one canonical record;
4. checks idempotency and conflicts;
5. appends one JSONL line;
6. flushes and fsyncs the file.

The registry uses an exclusive local lock file. Existing locks fail closed and are not removed automatically.

## Chain Verification

The verifier checks:

- genesis hash for the first record;
- previous-hash continuity;
- deterministic registry hashes;
- positions;
- duplicate IDs;
- conflicting IDs;
- unsafe raw-data markers;
- execution flags fixed to false.

Deletion, insertion, reordering, duplicate insertion, record mutation, invalid previous hash, malformed tails, and partial writes fail closed.

## Cross-Registry Reconciliation

The read-only cross-registry report links:

- persisted audit record;
- persisted runtime ledger record;
- persisted reconciliation attestation;
- persisted regulator export bundle.

It reports deterministic hash-only metadata and never repairs records.

## Human Approval Boundary

Persistence is not authorization. Registry validity is not authorization. Reconciliation consistency is not authorization. Attestation validity is not authorization. Export readiness and signing readiness are not authorization.

Human approval references remain hash/reference only. Approval contents are never serialized.

## Raw-Data Prohibition

The registry forbids raw payloads, approval contents, secrets, credentials, private keys, tokens, and certificate bodies. Optional signed auditor bundle, sealed archive, WORM, and timestamp references are stored only when already present as safe references.

## Retention Assumptions

The local registry does not delete, compact, migrate, repair, or externally persist records. External WORM persistence, live timestamping, live signing, regulator submission, and historical migration remain deferred governed work.

## Rollback

Rollback removes this additive registry layer and its tests/docs. Existing attestation, runtime ledger, audit evidence, validator APIs, approval behavior, and fail-closed decisions remain unchanged.
