# Production Integration Contracts

## Purpose

The Phase D1 production integration contracts define provider-neutral interfaces for future RFC3161 timestamp authority, external signing authority, WORM storage, object-lock storage, and regulator submission transport integrations.

This layer is contract-only. It does not connect to providers, call APIs, submit data, sign data, write WORM objects, create object locks, or activate production.

## Contract Boundaries

Each integration contract defines:

- request metadata;
- response metadata;
- deterministic receipt shape;
- status values;
- evidence references;
- correlation ID;
- tenant;
- policy version;
- timeout metadata;
- provider identifier;
- failure code;
- canonical serialization.

Receipts are hash-only and reference-only. Raw payloads, private keys, credentials, secrets, approval contents, certificate bodies, and access tokens are forbidden.

## Provider Responsibilities

Future providers must prove:

- exact required capability for the integration;
- provider identifier;
- tenant scope;
- policy version scope;
- supported guarantees;
- receipt schema;
- timeout boundary;
- hash-only evidence references.

Unsupported guarantees fail closed. Provider claims are never accepted as production readiness by themselves.

## USBAY Responsibilities

USBAY validates provider capability metadata, request metadata, receipt metadata, tenant and policy scope, timeout bounds, evidence references, deterministic hashes, duplicate receipts, and execution flags.

USBAY does not treat contract readiness as execution approval. Production readiness remains false unless a future governed capability proves every required external control.

## Fail-Closed Behavior

Unavailable adapters return explicit unavailable states:

- `RFC3161_UNAVAILABLE`
- `SIGNING_UNAVAILABLE`
- `WORM_UNAVAILABLE`
- `OBJECT_LOCK_UNAVAILABLE`
- `REGULATOR_TRANSPORT_UNAVAILABLE`

Unavailable adapters do not generate receipts, fake success, mutate policy, authorize execution, call providers, or activate production.

## Required Receipts

Future receipt adapters must emit `usbay.governance.production_integration_contracts.v1.receipt` records with deterministic hashes and references only. Invalid schemas, missing evidence references, fake success states, duplicate receipts, raw data, and execution-flag drift fail closed.

## Unsupported Guarantees

Providers may not claim broad execution, transport, signing, storage, retention, or submission guarantees outside the fixed guarantee set for their integration. Any unsupported claim blocks capability validation.

## Future Provider Adapter Order

1. RFC3161 timestamp authority
2. External signing authority
3. WORM storage
4. Object-lock storage
5. Regulator submission transport

## Rollback

Rollback removes this additive contract layer, receipt schema, tests, and documentation. Existing governance validators, evidence contracts, approval behavior, runtime decisions, and fail-closed behavior remain unchanged.
