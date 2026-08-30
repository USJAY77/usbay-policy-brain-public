# Regulator Export Pack

Planning status: architecture draft only. No runtime enforcement, production code, CI, or export behavior is changed by this document.

## Scope

The Regulator Export Pack is a proposed portable, customer-scoped export structure that packages hash-only evidence summaries for regulatory review. It would include customer evidence, deployment certificate chain, proof-of-use ledger, retention policy, and verification reports.

```
Customer Evidence Head
      |
      +--> Deployment Certificate Summary
      +--> Proof-of-Use Ledger Summary
      +--> Retention Policy Summary
      +--> Verification Report
      |
      v
Regulator Export Pack
```

## Trust Boundaries

- Customer boundary: only the selected tenant hash is exported.
- Regulator boundary: regulator receives proof summaries and hashes, not raw runtime payloads.
- Signing boundary: export pack manifest is signed after canonical hash calculation.
- Retention boundary: exports honor legal hold and retention windows.

## Evidence Flow

1. Select customer and regulator profile.
2. Resolve customer evidence head.
3. Include deployment certificate and proof-of-use summaries.
4. Compute canonical export manifest hash.
5. Sign export pack envelope.
6. Produce verification report.

## Signing Flow

```
export manifest
      |
      v
export manifest hash
      |
      v
export signing authority
      |
      v
signed regulator export pack
```

## Hash-Chain Design

Export pack records should include:

- `customer_evidence_head_hash`
- `deployment_certificate_chain_hash`
- `proof_of_use_ledger_hash`
- `retention_policy_hash`
- `verification_report_hash`
- `previous_export_pack_hash`
- `current_export_pack_hash`

## Customer Isolation Model

The export pack must reject mixed-tenant evidence, foreign deployment certificates, foreign proof-of-use entries, and cross-customer retention policy references.

## Rollback Model

Export rollback means revoking or superseding the export with a new append-only export record. Existing export packs are never overwritten.

## Governance Replay Model

Replay validates export pack hash, customer evidence head, certificate chain, proof-of-use ledger, retention policy, and signature chain. Missing evidence blocks export.

## Evidence Retention Policy

Export packs are retained according to regulator profile, customer agreement, and legal hold. Deletion is prohibited while any retention dependency remains active.

## Regulator Export Structure

The pack should contain:

- `export_manifest.json`
- `customer_evidence_index.json`
- `deployment_certificate_chain_summary.json`
- `proof_of_use_ledger_summary.json`
- `retention_policy_summary.json`
- `verification_report.md`
- `signatures.json`

## 🔍 GAP

Existing evidence artifacts need a customer-specific regulator packaging model with consistent hash-only summaries and verification reports.

## ⚠️ RISK

Ad hoc export assembly can omit required evidence, include foreign tenant references, or expose sensitive runtime material.

## ✅ MECHANISM

Create signed regulator export packs that bind customer evidence, deployment certificates, proof-of-use ledger, and retention policy into one canonical manifest.

## 🔘 AUDIT

Audit evidence is the export manifest hash, customer evidence head hash, component summary hashes, signature verification result, and retention policy hash.

## 👥 IMPACT

Regulators and customers receive a portable evidence package that is verifiable without raw payload exposure or runtime trust assumptions.
