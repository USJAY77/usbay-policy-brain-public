# Customer Evidence Layer

Planning status: architecture draft only. No runtime enforcement, production code, CI, or storage behavior is changed by this document.

## Scope

The Customer Evidence Layer is a proposed local-first evidence boundary for customer-visible governance proof. It would assemble hash-only, append-only records from deployment certificates, proof-of-use ledger entries, regulator export packs, and customer attestations without logging raw payloads, approval contents, secrets, or customer data.

```
Customer Tenant
      |
      v
+---------------------+      +--------------------+
| Evidence Collector  | ---> | Hash-Only Envelope |
+---------------------+      +--------------------+
                                      |
                                      v
                              +---------------+
                              | Evidence Head |
                              +---------------+
                                      |
                                      v
                              +----------------+
                              | Export Profile |
                              +----------------+
```

## Trust Boundaries

- Customer boundary: tenant-scoped identifiers and customer-facing attestations only.
- Runtime boundary: runtime enforcement evidence is referenced by hash, never copied as raw evidence.
- Signing boundary: signing authority signs canonical evidence envelopes only.
- Regulator boundary: regulator exports receive redacted metadata, hash chains, and verification summaries.

## Evidence Flow

1. Collect customer-scoped evidence references.
2. Normalize evidence metadata into deterministic canonical JSON.
3. Bind `tenant_id_hash`, `deployment_id_hash`, and evidence object hashes.
4. Append the evidence envelope to the customer evidence chain.
5. Export regulator/customer summaries without raw payload material.

## Signing Flow

```
canonical evidence envelope
        |
        v
sha256 envelope hash
        |
        v
signing authority
        |
        v
signed customer evidence record
```

## Hash-Chain Design

Each record should include:

- `previous_customer_evidence_hash`
- `current_customer_evidence_hash`
- `tenant_id_hash`
- `deployment_certificate_hash`
- `proof_of_use_hash`
- `regulator_export_hash`
- `attestation_flow_hash`

Chain validation must fail closed on missing previous hash, duplicate position, tenant mismatch, or non-canonical record encoding.

## Customer Isolation Model

Customer evidence chains must be tenant-scoped. No chain entry may reference another tenant's evidence, deployment certificate, regulator export, or attestation. Cross-tenant references must be treated as evidence corruption.

## Rollback Model

Rollback must not delete or rewrite evidence. A rollback creates a new append-only event referencing:

- rolled-back deployment hash
- approved rollback decision hash
- previous evidence head hash
- new evidence head hash

## Governance Replay Model

Replay verification reconstructs the hash chain from the first customer evidence record to the current head. Any missing record, reordered record, duplicate evidence identifier, or stale authority reference blocks verification.

## Evidence Retention Policy

Evidence retention should include:

- default retention class
- customer contractual retention window
- legal hold marker
- delete-prohibited-before timestamp
- regulator export retention tag

Deletion must fail closed during retention or legal hold.

## Regulator Export Structure

Exports should contain:

- customer evidence index
- hash-chain head
- deployment certificate chain summary
- proof-of-use ledger summary
- regulator profile manifest
- customer attestation summary
- verification report

## 🔍 GAP

USBAY has governance evidence primitives, but no customer-facing aggregation boundary that proves customer-specific governance history without exposing raw runtime evidence.

## ⚠️ RISK

Without a customer evidence layer, customer audit exports may be manually assembled, creating cross-tenant leakage risk, incomplete lineage, and inconsistent regulator evidence.

## ✅ MECHANISM

Introduce a hash-only, tenant-scoped, append-only customer evidence chain that references existing governance evidence by canonical hash and signed metadata.

## 🔘 AUDIT

Audit evidence is the customer evidence head hash, signed envelope hash, tenant binding hash, export profile hash, and deterministic replay report.

## 👥 IMPACT

Customers receive verifiable governance evidence without receiving raw payloads, secrets, approval contents, or unrelated tenant records.
