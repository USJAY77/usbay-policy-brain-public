# Audit Evidence Persistence Adapter

## Purpose

The audit evidence persistence adapter connects completed `AuditPipelineSummary` metadata to a local append-only JSONL audit-chain file. It is opt-in evidence handling only. It does not authorize execution, change validator outputs, or make persistence a prerequisite for an allow decision.

## Existing Storage Inventory

Current repository storage patterns include:

- `governance.audit_evidence.build_audit_chain_record` and `verify_audit_chain_records` for canonical previous-hash audit records.
- `runtime.computer_use.audit_chain.append_decision_record` and `verify_chain` for local decision-chain metadata.
- `governance.audit_registry.build_audit_registry` over immutable registry records.
- `governance.evidence_record_chain` for sealed-archive evidence renewal chains with previous-hash and append-only positions.
- WORM, sealed audit archive, signed auditor bundle, regulator export, and RFC3161-adjacent modules that consume hash-only records and reject unsafe diagnostics.

These systems are local-first and deterministic. Durable external WORM storage, external timestamping, and regulator submission are still separate governed capabilities.

## Supported Storage

The adapter supports local JSONL append-only persistence. Every line is one canonical JSON record. The adapter verifies the existing file before appending and refuses to append if the current chain is malformed.

The adapter does not provide record replacement, mutation, deletion, migration, cloud storage, Redis, Kafka, queues, credentials, network calls, or production activation.

## Required Pipeline State

Only completed and valid `AuditPipelineSummary` records are accepted. The summary must contain the fixed validator sequence:

1. policy validation
2. approval validation
3. signature validation
4. manifest validation
5. evidence validation
6. evidence-chain validation
7. WORM validation
8. regulator export validation
9. signed-bundle validation
10. production-readiness validation

The persistence context must provide evidence ID, governance decision, timestamp, and expected previous hash.

## Persisted Fields

Records persist only redacted metadata and hashes:

- position
- previous hash
- correlation ID
- tenant
- policy version
- evidence ID
- governance decision
- persisted timestamp
- validator-sequence hash
- stage count
- stage audit hashes
- stage canonical payload hashes
- canonical payload hash
- audit hash
- record hash
- execution flags fixed to false

Raw evidence, raw approvals, payloads, certificates, private keys, tokens, credentials, secrets, and provider data are forbidden.

## Append-Only Guarantees

Before append, the adapter verifies:

- record positions
- previous-hash continuity
- record hash integrity
- duplicate correlation IDs
- duplicate audit hashes
- tenant continuity
- policy-version continuity
- hash format
- execution flags
- raw-data markers

Invalid records are never written by the adapter.

## Idempotency

Repeated persistence of the same correlation ID and identical hash metadata returns `ALREADY_PERSISTED` without writing a second record. The same correlation ID with different content returns `AUDIT_PIPELINE_PERSISTENCE_CORRELATION_CONFLICT`.

## Atomicity Assumptions

The adapter uses a local exclusive lock file beside the JSONL store. If the lock exists, the adapter fails closed with `AUDIT_PIPELINE_PERSISTENCE_LOCKED`; it does not remove stale locks.

If an interrupted write leaves a malformed tail record, future appends fail closed with `AUDIT_PIPELINE_PERSISTENCE_RECORD_MALFORMED`. No partial line can become valid evidence because every line must parse as JSON and match its deterministic record hash.

## Tenant And Policy Isolation

The record binds tenant and policy version into the audit hash. Duplicate audit hashes under incompatible tenant or policy context are blocked as tenant or policy crossover.

## Failure Behavior

Persistence is additive. A blocked governance decision remains blocked. A successful write does not create authorization. A failed write returns a deterministic `BLOCKED` persistence result and never fabricates a successful audit record.

## Export Compatibility

Compatible by hash reference:

- audit-chain verification
- audit registry inspection
- evidence-chain verification
- WORM evidence planning
- sealed audit archive packaging
- signed auditor bundle packaging
- regulator export profile construction

Deferred:

- direct WORM object-lock persistence
- external timestamp authority submission
- regulator filing
- signed bundle inclusion of the JSONL file itself
- migration of historical audit records

Those integrations must remain separate governed batches.
