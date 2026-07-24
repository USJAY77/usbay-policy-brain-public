# Runtime Ledger Persistence And Reconciliation

## Purpose

The runtime ledger persistence adapter links completed audit-pipeline persistence records to governance runtime ledger entries. It is opt-in and additive. It does not authorize execution, change validator outputs, repair chains, or rewrite history.

## Integration Inventory

Existing links:

- `AuditPipelineSummary.correlation_id` links validator-stage evidence.
- Audit persistence records bind correlation ID, tenant, policy version, evidence ID, governance decision, canonical payload hash, audit hash, previous hash, and record hash.
- Runtime ledger entries bind tenant, policy version, validator, decision, failure code, evidence ID, audit hash, previous hash, correlation ID, and entry hash.
- Audit registry, evidence chain, WORM, sealed archive, signed auditor bundle, regulator export, and production-readiness modules consume hash-only evidence references.

Missing links addressed here:

- one-to-one linkage between persisted audit record and runtime ledger entry;
- deterministic reconciliation report;
- read-only orphan detection between audit persistence and ledger persistence.

## Append Order

Safe order:

1. validate the original governance result;
2. generate audit evidence;
3. build the audit pipeline summary;
4. persist the audit pipeline record;
5. build the runtime ledger entry from the persisted audit reference;
6. persist the runtime ledger reference record;
7. reconcile audit record, ledger entry, and stored ledger record.

No ledger persistence record may reference a nonexistent persisted audit record.

## Persisted References

The ledger persistence record stores only:

- reconciliation ID
- correlation ID
- tenant
- policy version
- evidence ID
- governance decision
- failure code
- audit hash
- canonical payload hash
- audit record hash
- ledger ID
- ledger entry hash
- ledger previous hash
- audit chain position
- ledger chain position
- checked timestamp
- execution flags fixed to false

Raw payloads, approval contents, signatures, certificates, credentials, tokens, prompts, secrets, provider data, and private keys are forbidden.

## Reconciliation Contract

A consistent reconciliation requires matching:

- correlation ID
- tenant
- policy version
- evidence ID
- audit hash
- governance decision
- failure code where represented
- canonical payload hash
- previous hash
- persisted audit record hash
- persisted ledger entry hash

Result states include `CONSISTENT`, orphan states, mismatch states, duplicate states, malformed state, incomplete-context state, and storage-failure state.

## Idempotency And Conflict Behavior

An identical retry returns `ALREADY_PERSISTED` and writes no second record. The same correlation ID with different logical content fails closed as `CORRELATION_CONFLICT`.

Duplicate audit hashes under a different tenant or policy version fail closed as tenant or policy mismatch. Duplicate evidence IDs under incompatible policy versions also fail closed.

## Atomicity Assumptions

The adapter uses the same local JSONL plus exclusive lock pattern as audit-pipeline persistence. If a lock already exists, persistence fails closed. Malformed existing records or partial tails block future appends. No automatic stale-lock removal is performed.

## Orphan Detection

Set reconciliation is read-only. It detects:

- audit record without ledger record;
- ledger record without audit record;
- duplicate correlations;
- malformed audit or ledger chains.

This batch does not repair or delete records.

## Export Compatibility

Compatible by hash/reference:

- audit registry;
- evidence-chain verifier;
- WORM verification;
- sealed audit archive;
- signed auditor bundle;
- regulator export profile.

Deferred:

- live WORM persistence;
- external timestamp authority;
- regulator submission;
- automatic historical migration;
- automatic repair.

## Governance Preservation

Persistence and reconciliation are not authorization. A blocked decision remains blocked. A successful reconciliation does not enable execution. All records and reports preserve:

- `execution_allowed=false`
- `provider_execution=false`
- `production_activation=false`
- `runtime_execution=false`
- `deployment_execution=false`
- `policy_mutation=false`
- `network_access=false`
