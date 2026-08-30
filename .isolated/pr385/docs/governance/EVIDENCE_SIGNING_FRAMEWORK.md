# Evidence Signing Framework

Purpose: define a cryptographic evidence signing framework that binds evidence packages, validation results, review decisions, export bundles, timestamp records, and audit lineage records to verifiable signatures.

Runtime impact: none.

AWS resource creation: none.

Credentials stored in repository: prohibited.

Private keys stored in repository: prohibited.

Certification claim: prohibited.

Blocker status change: prohibited.

Default decision: BLOCKED.

## Framework Files

Signature framework files:

- `governance/signatures/signature_schema.json`
- `governance/signatures/signature_example.json`
- `governance/signatures/signature_relationships.md`
- `scripts/verify_signatures.py`

## Signature Record Schema

Every signature record must include:

- Signature record ID.
- Signature subject type.
- Signature subject ID.
- Signature subject path.
- Signature subject SHA256.
- Signature algorithm.
- Signature value.
- Public key reference.
- Public key SHA256.
- Signer identity.
- Signing policy reference.
- Timestamp record ID.
- Timestamp record SHA256.
- Previous signature record SHA256.
- Current signature record SHA256.
- Linked audit reference.
- Decision.

## Signature Chain Validation

Signature chain validation verifies:

- Required signature records exist.
- Required subject types exist.
- Signature subject paths exist.
- Required hashes are valid SHA256 strings.
- Signature algorithms are explicitly allowed.
- Signature values exist.
- Public key references exist.
- Private keys are not present.
- Timestamp linkage exists.
- Previous/current signature record hashes preserve continuity.
- Required relationships exist.

This verifier checks metadata completeness and chain continuity only. It does not perform live cryptographic verification against private key material, provider services, or external trust services.

## Evidence Signature Linkage

Evidence package signature records bind:

- Evidence package path.
- Evidence package hash.
- Signature metadata.
- Timestamp record linkage.
- Audit reference.

## Validation Signature Linkage

Validation signature records bind:

- Validation result path.
- Validation result hash.
- Signer identity.
- Signature metadata.
- Timestamp record linkage.

## Review Signature Linkage

Review signature records bind:

- Review decision path.
- Review decision hash.
- Reviewer identity reference.
- Signature metadata.
- Timestamp record linkage.

## Export Signature Linkage

Export signature records bind:

- Export bundle path.
- Export bundle hash.
- Bundle verification reference.
- Signature metadata.
- Timestamp record linkage.

## Timestamp Signature Linkage

Timestamp signature records bind:

- Timestamp record path.
- Timestamp record hash.
- Signature metadata.
- Previous signature hash.
- Current signature hash.

## Audit Lineage Signature Linkage

Audit lineage signature records bind:

- Audit lineage path.
- Audit lineage hash.
- Signature metadata.
- Previous signature hash.
- Current signature hash.
- Linked audit reference.

## Missing And Invalid Signature Detection

Missing signature detection emits:

```text
SIGNATURE_MISSING
```

Invalid signature detection emits:

```text
SIGNATURE_INVALID
```

Incomplete signature chain detection emits:

```text
SIGNATURE_CHAIN_INCOMPLETE
```

## Fail-Closed Verification

Run:

```text
python3 scripts/verify_signatures.py
```

Placeholder expected result:

```text
Decision = BLOCKED
SIGNATURE_MISSING
SIGNATURE_INVALID
SIGNATURE_CHAIN_INCOMPLETE
```

Signature verification passes only when all required signature records, relationships, subject paths, hashes, allowed algorithms, timestamp linkages, audit references, and chain continuity values exist and verify.

This framework does not create or store keys.

This framework does not create certification claims.

This framework does not change blocker status.
