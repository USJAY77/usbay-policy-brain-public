# Customer Governance Attestation Flow

Planning status: architecture draft only. No runtime enforcement, production code, CI, or attestation behavior is changed by this document.

## Scope

The Customer Governance Attestation Flow is a proposed process for generating customer-facing attestations that a specific deployment, policy bundle, evidence chain, and export pack were governed under USBAY controls.

```
Customer Evidence Layer
          |
          v
Attestation Request Hash
          |
          v
Human Review Boundary
          |
          v
Signed Customer Attestation
          |
          v
Regulator or Customer Review
```

## Trust Boundaries

- Customer boundary: attestations bind only to one tenant hash.
- Human review boundary: high-impact attestations require explicit approval decision hash.
- Signing boundary: attestation signer signs only canonical attestation payloads.
- Export boundary: attestation references export pack hashes, not raw evidence.

## Evidence Flow

1. Resolve customer evidence head and requested attestation scope.
2. Verify deployment certificate chain and proof-of-use ledger hashes.
3. Require human review for customer-facing claims.
4. Create canonical attestation record.
5. Sign the attestation and append it to the customer evidence chain.

## Signing Flow

```
attestation scope + evidence hashes
          |
          v
canonical attestation payload
          |
          v
attestation hash
          |
          v
customer attestation signer
```

## Hash-Chain Design

Attestation records should include:

- `previous_attestation_hash`
- `current_attestation_hash`
- `tenant_id_hash`
- `customer_evidence_head_hash`
- `deployment_certificate_hash`
- `proof_of_use_ledger_hash`
- `regulator_export_pack_hash`
- `human_review_decision_hash`

## Customer Isolation Model

Attestations cannot reference evidence from another customer. A mismatch between tenant hash, evidence head, export pack, or deployment certificate must fail closed.

## Rollback Model

Attestation rollback is a superseding attestation event that references the original attestation hash and the human-approved correction hash. The original remains part of chronology.

## Governance Replay Model

Replay validates attestation scope, human review decision hash, customer evidence head, signature, and referenced export pack. Missing or unsigned attestation metadata blocks verification.

## Evidence Retention Policy

Attestations must retain for the longest applicable customer, regulator, legal hold, and dispute window. Superseded attestations remain retained.

## Regulator Export Structure

Exports include attestation hash, signer identity hash, customer evidence head hash, human review decision hash, referenced export pack hash, and verification summary.

## 🔍 GAP

Customers need a governed attestation flow that explains what USBAY can prove without exposing internal runtime data.

## ⚠️ RISK

Without explicit attestation boundaries, customer-facing claims may become broader than the evidence supports.

## ✅ MECHANISM

Use signed, tenant-scoped customer attestations that bind evidence head, deployment certificate, proof-of-use ledger, export pack, and human review decision hashes.

## 🔘 AUDIT

Audit evidence is the attestation hash, signer identity hash, customer evidence head hash, human review decision hash, and replay verification report.

## 👥 IMPACT

Customers receive clear, evidence-backed governance attestations while sensitive governance payloads and approvals remain protected.
