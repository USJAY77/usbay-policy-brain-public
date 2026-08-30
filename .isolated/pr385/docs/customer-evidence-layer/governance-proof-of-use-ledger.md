# Governance Proof-of-Use Ledger

Planning status: architecture draft only. No runtime enforcement, production code, CI, or ledger behavior is changed by this document.

## Scope

The Governance Proof-of-Use Ledger is a proposed customer-scoped ledger proving that governance controls were used for customer-relevant decisions. It records hash-only references to decisions, policy evaluations, approvals, denials, replay checks, and evidence exports.

```
Governance Decision Hash
          |
          v
Proof-of-Use Entry
          |
          v
Customer Proof-of-Use Ledger Head
          |
          v
Customer Evidence Layer
```

## Trust Boundaries

- Runtime boundary: runtime decisions are referenced by decision hash only.
- Policy boundary: policy version and policy hash are included, not raw policy exceptions.
- Approval boundary: approval decision hash is included, not approval content.
- Customer boundary: tenant hash scopes every entry.

## Evidence Flow

1. Receive a governance decision reference.
2. Verify tenant hash, policy hash, decision ID hash, and timestamp freshness.
3. Canonicalize a proof-of-use entry.
4. Append to the customer proof-of-use ledger.
5. Reference the proof-of-use head from customer evidence exports.

## Signing Flow

```
proof-of-use entry
      |
      v
entry hash
      |
      v
ledger signing authority
      |
      v
signed proof-of-use record
```

## Hash-Chain Design

Ledger entries should include:

- `previous_proof_of_use_hash`
- `current_proof_of_use_hash`
- `tenant_id_hash`
- `decision_id_hash`
- `policy_hash`
- `runtime_authority_hash`
- `approval_decision_hash`
- `replay_validation_hash`

## Customer Isolation Model

Each ledger is tenant-specific. Entries from different tenants cannot share chain heads, previous hashes, decision IDs, approval hashes, or export references.

## Rollback Model

Rollback is represented as a new proof-of-use event that references the original decision and rollback decision hash. The earlier record remains immutable.

## Governance Replay Model

Replay validates every proof-of-use entry against the customer ledger head, policy hash continuity, approval decision hash, replay validation hash, and runtime authority hash.

## Evidence Retention Policy

Proof-of-use records should retain for the maximum of customer contract, regulator export, legal hold, and active dispute windows.

## Regulator Export Structure

Exports include ledger head hash, entry count, decision hash list, policy hash list, denial/approval summary, replay validation summary, and no raw request or approval content.

## 🔍 GAP

Governance decisions may be auditable internally but not packaged as customer-specific proof that controls were actually applied.

## ⚠️ RISK

Without proof-of-use, customers may receive deployment evidence without decision-level control usage evidence.

## ✅ MECHANISM

Add a tenant-scoped, append-only ledger of hash-only governance decision references with replay validation binding.

## 🔘 AUDIT

Audit evidence is the proof-of-use ledger head hash, decision hash list, policy hash continuity, approval decision hash references, and replay validation hash.

## 👥 IMPACT

Customers can verify that governance controls were applied to their relevant actions without exposure to raw payloads or approval contents.
