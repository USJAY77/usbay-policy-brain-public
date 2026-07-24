# Reconciliation Attestation And Regulator Export Bundle

## Purpose

The reconciliation attestation layer converts a successful audit-to-runtime-ledger reconciliation into signed-ready, regulator-exportable reference metadata. It remains local, deterministic, hash-only, and non-executing.

## Compatibility Inventory

Compatible existing paths by reference:

- audit evidence and audit-pipeline persistence records;
- runtime ledger persistence records;
- audit registry records;
- evidence-chain verification;
- WORM evidence references;
- sealed audit archive references;
- signed auditor bundle references;
- signed bundle timestamp references;
- regulator export profile references;
- production-readiness evidence references.

Missing/deferred paths:

- live signing;
- external timestamp authority submission;
- live WORM object-lock persistence;
- regulator submission;
- historical record migration;
- automatic record repair.

No compatible path requires raw governance payloads for this layer. Raw payloads, approval contents, certificates, private keys, credentials, secrets, prompts, and tokens are forbidden.

## Reconciliation To Attestation Flow

An attestation can be created only when reconciliation is `CONSISTENT` or `ALREADY_RECONCILED`. The attestation binds:

- reconciliation ID;
- correlation ID;
- tenant;
- policy version;
- evidence ID;
- governance decision;
- failure code;
- audit record hash;
- runtime ledger record hash;
- runtime ledger entry hash;
- reconciliation report hash;
- audit-chain reference;
- ledger-chain reference;
- validator sequence hash;
- canonical payload hash;
- issued timestamp;
- attestation version;
- attestation hash.

All hashes use canonical sorted-key JSON.

## Export Eligibility Gate

A regulator export bundle can be generated only from a valid attestation and matching audit and runtime-ledger records. The gate blocks missing records, mismatched tenant, mismatched policy version, mismatched evidence ID, mismatched decision, mismatched failure code, invalid chain references, duplicate records, conflicts, and raw-data markers.

The bundle contains hashes and references only.

## Bundle Fields

The export bundle includes:

- export bundle ID;
- export profile;
- jurisdiction reference;
- tenant;
- policy version;
- evidence ID;
- reconciliation attestation reference;
- audit record reference;
- runtime ledger reference;
- audit-chain reference;
- ledger-chain reference;
- signed auditor bundle reference;
- sealed archive reference;
- WORM reference;
- timestamp reference;
- generated timestamp;
- bundle version;
- bundle manifest hash.

## Signing Compatibility

The signing input binds:

- reconciliation attestation hash;
- regulator export bundle manifest hash;
- audit record hash;
- runtime ledger record hash;
- audit-chain reference;
- ledger-chain reference;
- tenant;
- policy version;
- evidence ID.

This layer does not perform signing, read private keys, inspect certificate bodies, or change trust-anchor, revocation, timestamp, or certificate validation semantics.

## Human Approval Boundary

Attestation is not authorization. Export eligibility is not authorization. Signing readiness is not authorization. Regulatory export readiness is not authorization. Successful export-bundle generation does not permit execution.

Human approval metadata remains external hash/reference metadata only. No approval content is fabricated.

## Duplicate And Conflict Behavior

Identical attestation or export-bundle generation is deterministic and idempotent at the logical-record level. Duplicate attestation references are detected. Same reconciliation ID with different content is an attestation conflict. Same correlation with incompatible hashes, tenant, policy, evidence, decision, or failure code fails closed.

## Deferred External Operations

Deferred operations require separate governed implementation:

- live digital signatures;
- regulator submission;
- timestamp authority calls;
- external WORM persistence;
- cloud storage;
- automatic repair or migration.

## Rollback

Rollback removes this additive attestation/export-bundle layer and its tests/docs. Existing reconciliation, runtime ledger, audit evidence, validator APIs, approval behavior, production readiness, and fail-closed decisions remain unchanged.
