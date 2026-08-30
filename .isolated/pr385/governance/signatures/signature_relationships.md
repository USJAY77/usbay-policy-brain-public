# Evidence Signature Relationships

Purpose: define cryptographic signature relationships across evidence packages, validation results, review decisions, export bundles, timestamp records, and audit lineage records.

Runtime impact: none.

AWS resource creation: none.

Credentials and private keys in repository: prohibited.

Certification claim: prohibited.

Default decision: BLOCKED.

## Required Signature Chain

The evidence signing chain must link:

1. Evidence package signature to validation result signature.
2. Validation result signature to review decision signature.
3. Review decision signature to export bundle signature.
4. Export bundle signature to timestamp record signature.
5. Timestamp record signature to audit lineage signature.

If any signature is missing:

Decision = BLOCKED

Failure code: SIGNATURE_MISSING

If any signature is malformed, uses an undocumented algorithm, lacks a public key reference, lacks signer identity, or cannot be tied to a subject hash:

Decision = BLOCKED

Failure code: SIGNATURE_INVALID

If any signature chain link is missing or inconsistent:

Decision = BLOCKED

Failure code: SIGNATURE_CHAIN_INCOMPLETE

## Evidence Signature Records

Evidence signature records must include:

- Evidence package path.
- Evidence package SHA256 hash.
- Signature algorithm.
- Signature value.
- Public key reference.
- Public key SHA256 hash.
- Signer identity.
- Signing policy reference.
- Timestamp record linkage.
- Previous signature record hash.
- Current signature record hash.

## Validation Signature Records

Validation signature records must bind:

- Validation result path.
- Validation result SHA256 hash.
- Validation actor or service identity.
- Signature value.
- Public key reference.
- Timestamp record linkage.

## Review Signature Records

Review signature records must bind:

- Review decision path.
- Review decision SHA256 hash.
- Reviewer identity reference.
- Signature value.
- Public key reference.
- Timestamp record linkage.

Human approval is not evidence unless the review decision is signed, timestamp-linked, and audit-linked.

## Export Signature Records

Export signature records must bind:

- Export bundle path.
- Export bundle SHA256 hash.
- Bundle verification result.
- Signature value.
- Public key reference.
- Timestamp record linkage.

## Timestamp Signature Linkage

Timestamp signature records must bind:

- Timestamp record path.
- Timestamp record SHA256 hash.
- Signature value.
- Public key reference.
- Previous signature record hash.
- Current signature record hash.

## Audit Lineage Signature Linkage

Audit lineage signature records must bind:

- Lineage record path.
- Lineage record SHA256 hash.
- Signature value.
- Public key reference.
- Previous signature record hash.
- Current signature record hash.
- Linked audit reference.

## Fail-Closed Verification

Signature verification must fail closed when:

- Required signature record is missing.
- Signature subject path is missing.
- Signature subject hash is missing.
- Signature algorithm is missing or unsupported.
- Signature value is missing.
- Public key reference is missing.
- Public key hash is missing.
- Signer identity is missing.
- Signing policy reference is missing.
- Timestamp linkage is missing.
- Previous/current signature record hash continuity is incomplete.

Fail-closed output:

Decision = BLOCKED

SIGNATURE_MISSING

SIGNATURE_INVALID

SIGNATURE_CHAIN_INCOMPLETE

## Governance Boundary

This framework does not create AWS resources, store credentials, store private keys, change runtime behavior, change blocker status, or make certification claims.

BLOCKER-003 remains OPEN until real provider evidence is signed, timestamp-linked, independently validated, and reviewed through the governed certification process.
