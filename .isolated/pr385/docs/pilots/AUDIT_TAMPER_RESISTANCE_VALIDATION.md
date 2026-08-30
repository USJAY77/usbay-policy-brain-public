# Audit Chain Tamper Resistance Validation

Purpose: validate that USBAY evidence lineage, signatures, timestamps, WORM archive records, and export bundles detect unauthorized modification and fail closed.

Runtime impact: none.

Credentials committed: none.

Private keys committed: none.

Provider secrets committed: none.

Raw approvals committed: none.

Certification claim: none.

Blocker status change: none.

Default decision: BLOCKED.

Required governance rule:

- Evidence before claims.
- USBAY decides.
- Humans approve.
- Fail closed by default.

## Validation Scope

This hardening pilot validates five tamper scenarios:

1. Modified evidence package.
2. Modified signature.
3. Modified timestamp.
4. Modified export bundle.
5. Missing audit record.

Every scenario must produce:

- Verification fails.
- Audit chain broken.
- Fail-closed triggered.
- Evidence marked invalid.

This pilot is documentation-only. It does not modify runtime behavior, provider resources, gateway logic, policy enforcement logic, audit history, credentials, private keys, or certification status.

## Baseline Chain

The baseline chain uses deterministic, non-secret identifiers and hash references. No raw evidence payload, credential, private key, provider secret, raw approval, or raw regulator export is included.

| Field | Baseline value |
| --- | --- |
| Request ID | `request-tamper-20260603-001` |
| Evidence ID | `evidence-tamper-20260603-001` |
| Review ID | `review-tamper-20260603-001` |
| Decision ID | `decision-tamper-20260603-001` |
| Signature ID | `signature-tamper-20260603-001` |
| Timestamp ID | `timestamp-tamper-20260603-001` |
| Archive ID | `archive-tamper-20260603-001` |
| Export Bundle ID | `export-bundle-tamper-20260603-001` |
| Verification ID | `verification-tamper-20260603-001` |
| Baseline Evidence Hash | `sha256:baseline-evidence-hash-reference` |
| Baseline Signature Hash | `sha256:baseline-signature-hash-reference` |
| Baseline Timestamp Hash | `sha256:baseline-timestamp-hash-reference` |
| Baseline Export Hash | `sha256:baseline-export-bundle-hash-reference` |
| Baseline Audit Chain Hash | `sha256:baseline-audit-chain-hash-reference` |

Baseline verification may pass only when every required relationship is present and every hash reference matches the expected chain state.

## Required Verification Controls

Verification must check:

- Evidence package hash continuity.
- Signature artifact hash continuity.
- Timestamp subject hash continuity.
- WORM archive manifest hash continuity.
- Export bundle manifest hash continuity.
- Audit record presence.
- Chain-of-custody continuity.
- Review-to-decision linkage.
- Decision-to-signature linkage.
- Signature-to-timestamp linkage.
- Timestamp-to-archive linkage.
- Archive-to-export linkage.
- Export-to-verification linkage.

If any verification control fails:

```text
Decision = BLOCKED
Evidence Status = INVALID
Audit Chain Status = BROKEN
```

## Scenario 1: Modified Evidence Package

Tamper action:

```text
Evidence package content changes after review, signature, timestamp, archive, or export.
```

Expected detection:

- Evidence package SHA256 no longer matches the reviewed evidence hash.
- Review record references the original evidence hash, not the modified evidence hash.
- Signature subject hash no longer matches the evidence package.
- Export bundle evidence hash list no longer matches the current evidence package.

Expected outcome:

| Field | Value |
| --- | --- |
| Verification Result | `FAILED` |
| Audit Chain Status | `BROKEN` |
| Fail-Closed Status | `true` |
| Evidence Status | `INVALID` |
| Fail-Closed Reason | `EVIDENCE_HASH_MISMATCH` |

Required decision:

```text
Decision = BLOCKED
```

## Scenario 2: Modified Signature

Tamper action:

```text
Signature value, signature metadata, public key reference, or signed artifact reference changes after signature generation.
```

Expected detection:

- Signature hash no longer matches the signature record.
- Public key reference no longer validates against the signed artifact.
- Timestamp record references the original signature hash, not the modified signature hash.
- Export bundle signature reference no longer matches the signature record.

Expected outcome:

| Field | Value |
| --- | --- |
| Verification Result | `FAILED` |
| Audit Chain Status | `BROKEN` |
| Fail-Closed Status | `true` |
| Evidence Status | `INVALID` |
| Fail-Closed Reason | `SIGNATURE_HASH_MISMATCH` |

Required decision:

```text
Decision = BLOCKED
```

## Scenario 3: Modified Timestamp

Tamper action:

```text
Timestamp value, timestamp token hash, timestamp subject reference, timestamp authority metadata, or timestamp chain reference changes after timestamp generation.
```

Expected detection:

- Timestamp token hash no longer matches the timestamp record.
- Timestamp subject hash no longer matches the signed artifact.
- WORM archive record references the original timestamp hash, not the modified timestamp.
- Export bundle timestamp reference no longer matches the timestamp record.

Expected outcome:

| Field | Value |
| --- | --- |
| Verification Result | `FAILED` |
| Audit Chain Status | `BROKEN` |
| Fail-Closed Status | `true` |
| Evidence Status | `INVALID` |
| Fail-Closed Reason | `TIMESTAMP_HASH_MISMATCH` |

Required decision:

```text
Decision = BLOCKED
```

## Scenario 4: Modified Export Bundle

Tamper action:

```text
Export manifest, evidence hash list, validation result, review decision, signature reference, timestamp reference, archive reference, chain-of-custody record, or bundle hash changes after export generation.
```

Expected detection:

- Export bundle manifest hash no longer matches the recorded export hash.
- Evidence hash list no longer maps to the baseline evidence package.
- Bundle verification record no longer matches the exported artifact.
- Tamper detection result changes from clean to failed.

Expected outcome:

| Field | Value |
| --- | --- |
| Verification Result | `FAILED` |
| Audit Chain Status | `BROKEN` |
| Fail-Closed Status | `true` |
| Evidence Status | `INVALID` |
| Fail-Closed Reason | `EXPORT_BUNDLE_HASH_MISMATCH` |

Required decision:

```text
Decision = BLOCKED
```

## Scenario 5: Missing Audit Record

Tamper action:

```text
Audit record, review record, decision record, signature record, timestamp record, archive record, export record, or verification record is removed or cannot be resolved.
```

Expected detection:

- Required audit identifier cannot be resolved.
- Chain-of-custody continuity is broken.
- Export bundle cannot prove complete lineage.
- Verification cannot reconstruct the decision from evidence.

Expected outcome:

| Field | Value |
| --- | --- |
| Verification Result | `FAILED` |
| Audit Chain Status | `BROKEN` |
| Fail-Closed Status | `true` |
| Evidence Status | `INVALID` |
| Fail-Closed Reason | `AUDIT_RECORD_MISSING` |

Required decision:

```text
Decision = BLOCKED
```

## Tamper Detection Matrix

| Scenario | Detection control | Required outcome |
| --- | --- | --- |
| Modified evidence package | Evidence hash mismatch | BLOCKED |
| Modified signature | Signature hash or validation mismatch | BLOCKED |
| Modified timestamp | Timestamp hash or subject mismatch | BLOCKED |
| Modified export bundle | Bundle manifest or hash mismatch | BLOCKED |
| Missing audit record | Lineage reconstruction failure | BLOCKED |

## Export Safety Requirements

Audit export must not contain:

- Credentials.
- Provider secrets.
- Private keys.
- Raw approvals.
- Raw regulator exports.
- Unredacted sensitive payloads.

If any prohibited material appears in exported artifacts:

```text
Decision = BLOCKED
Evidence Status = INVALID
Fail-Closed Reason = EXPORT_CONTAINS_PROHIBITED_MATERIAL
```

## Final Hardening Decision

Tamper resistance validation passes only when every unauthorized modification is detected and every detected modification fails closed.

Required result for every scenario:

```text
Verification = FAILED
Audit Chain = BROKEN
Decision = BLOCKED
Evidence Status = INVALID
```

Any tamper scenario that does not produce a blocked outcome is a governance failure and must prevent production readiness or certification claims.
