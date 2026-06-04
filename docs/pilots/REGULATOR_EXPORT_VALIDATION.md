# Regulator Evidence Export Package Validation

Purpose: validate that a regulator-facing USBAY evidence package can be exported, independently verified, reproduced, and rejected fail-closed when tampered or incomplete.

Runtime impact: none.

Credentials committed: none.

Private keys committed: none.

Provider secrets committed: none.

Raw approvals committed: none.

Raw regulator exports committed: none.

Certification claim: none.

Blocker status change: none.

Default decision: BLOCKED.

Required governance rule:

- Evidence before claims.
- USBAY decides.
- Humans approve.
- Fail closed by default.

## Validation Scope

This pilot validates:

1. Evidence package exported.
2. Audit chain exported.
3. Signature metadata exported.
4. Timestamp metadata exported.
5. Verification instructions included.
6. Tampered package verification fails.
7. Missing evidence package rejected.

Required output identifiers:

- Export Package ID.
- Audit Package ID.
- Verification Package ID.
- Signature Metadata ID.
- Timestamp Metadata ID.

This pilot is documentation-only. It does not export raw regulator data, create provider resources, store credentials, store private keys, modify runtime behavior, modify gateway logic, modify policy enforcement, make certification claims, or change blocker status.

## Regulator Export Package Record

The package record uses deterministic, non-secret identifiers and hash references. No raw approval content, credential, private key, provider secret, or raw regulator export is included.

| Field | Value |
| --- | --- |
| Export Package ID | `reg-export-package-20260603-001` |
| Audit Package ID | `reg-audit-package-20260603-001` |
| Verification Package ID | `reg-verification-package-20260603-001` |
| Signature Metadata ID | `reg-signature-metadata-20260603-001` |
| Timestamp Metadata ID | `reg-timestamp-metadata-20260603-001` |
| Evidence Package ID | `reg-evidence-package-20260603-001` |
| Audit Chain ID | `reg-audit-chain-20260603-001` |
| Export Manifest Hash | `sha256:regulator-export-manifest-hash-reference` |
| Evidence Package Hash | `sha256:regulator-evidence-package-hash-reference` |
| Audit Chain Hash | `sha256:regulator-audit-chain-hash-reference` |
| Verification Instructions Hash | `sha256:regulator-verification-instructions-hash-reference` |
| Export Status | `EXPORTED` |
| Verification Status | `VERIFIED` |

The export package is valid only when every required package identifier exists, every hash reference is reproducible, and the verification package can independently verify the exported package without private keys, credentials, provider secrets, or raw approvals.

## Scenario 1: Evidence Package Exported

Required export contents:

- Evidence Package ID.
- Evidence manifest hash.
- Evidence source references.
- Evidence hash list.
- Redaction statement.
- Scope boundary.

Validated record:

| Field | Value |
| --- | --- |
| Export Package ID | `reg-export-package-20260603-001` |
| Audit Package ID | `reg-audit-package-20260603-001` |
| Verification Package ID | `reg-verification-package-20260603-001` |
| Signature Metadata ID | `reg-signature-metadata-20260603-001` |
| Timestamp Metadata ID | `reg-timestamp-metadata-20260603-001` |
| Verification Result | `VERIFIED` |
| Failure Reason | `Information not provided` |

Expected outcome:

```text
Evidence Package Export = VERIFIED
```

Fail-closed condition:

```text
Decision = BLOCKED
Reason = EVIDENCE_PACKAGE_EXPORT_MISSING
```

## Scenario 2: Audit Chain Exported

Required export contents:

- Audit Package ID.
- Request reference.
- Evidence reference.
- Review reference.
- Decision reference.
- Signature metadata reference.
- Timestamp metadata reference.
- Archive reference.
- Export verification reference.
- Audit chain hash.

Validated record:

| Field | Value |
| --- | --- |
| Export Package ID | `reg-export-package-20260603-001` |
| Audit Package ID | `reg-audit-package-20260603-001` |
| Verification Package ID | `reg-verification-package-20260603-001` |
| Signature Metadata ID | `reg-signature-metadata-20260603-001` |
| Timestamp Metadata ID | `reg-timestamp-metadata-20260603-001` |
| Verification Result | `VERIFIED` |
| Failure Reason | `Information not provided` |

Expected outcome:

```text
Audit Chain Export = VERIFIED
```

Fail-closed condition:

```text
Decision = BLOCKED
Reason = AUDIT_CHAIN_EXPORT_MISSING
```

## Scenario 3: Signature Metadata Exported

Required export contents:

- Signature Metadata ID.
- Signature ID.
- Signed artifact hash.
- Public verification key reference.
- Signature algorithm reference.
- Signature verification result.
- Signature metadata hash.

Validated record:

| Field | Value |
| --- | --- |
| Export Package ID | `reg-export-package-20260603-001` |
| Audit Package ID | `reg-audit-package-20260603-001` |
| Verification Package ID | `reg-verification-package-20260603-001` |
| Signature Metadata ID | `reg-signature-metadata-20260603-001` |
| Timestamp Metadata ID | `reg-timestamp-metadata-20260603-001` |
| Verification Result | `VERIFIED` |
| Failure Reason | `Information not provided` |

Expected outcome:

```text
Signature Metadata Export = VERIFIED
```

Private keys must not be included in the export package.

Fail-closed condition:

```text
Decision = BLOCKED
Reason = SIGNATURE_METADATA_EXPORT_MISSING
```

## Scenario 4: Timestamp Metadata Exported

Required export contents:

- Timestamp Metadata ID.
- Timestamp ID.
- Timestamp subject hash.
- Timestamp evidence reference.
- Timestamp verification result.
- Timestamp metadata hash.

Validated record:

| Field | Value |
| --- | --- |
| Export Package ID | `reg-export-package-20260603-001` |
| Audit Package ID | `reg-audit-package-20260603-001` |
| Verification Package ID | `reg-verification-package-20260603-001` |
| Signature Metadata ID | `reg-signature-metadata-20260603-001` |
| Timestamp Metadata ID | `reg-timestamp-metadata-20260603-001` |
| Verification Result | `VERIFIED` |
| Failure Reason | `Information not provided` |

Expected outcome:

```text
Timestamp Metadata Export = VERIFIED
```

Fail-closed condition:

```text
Decision = BLOCKED
Reason = TIMESTAMP_METADATA_EXPORT_MISSING
```

## Scenario 5: Verification Instructions Included

Required export contents:

- Verification Package ID.
- Verification instructions hash.
- Manifest verification steps.
- Evidence hash verification steps.
- Signature verification steps.
- Timestamp verification steps.
- Audit chain reconstruction steps.
- Tamper detection criteria.
- Missing evidence rejection criteria.

Validated record:

| Field | Value |
| --- | --- |
| Export Package ID | `reg-export-package-20260603-001` |
| Audit Package ID | `reg-audit-package-20260603-001` |
| Verification Package ID | `reg-verification-package-20260603-001` |
| Signature Metadata ID | `reg-signature-metadata-20260603-001` |
| Timestamp Metadata ID | `reg-timestamp-metadata-20260603-001` |
| Verification Result | `VERIFIED` |
| Failure Reason | `Information not provided` |

Expected outcome:

```text
Independent Verification = POSSIBLE
```

Fail-closed condition:

```text
Decision = BLOCKED
Reason = VERIFICATION_INSTRUCTIONS_MISSING
```

## Scenario 6: Tampered Package Verification Fails

Tamper action:

```text
Export manifest, evidence hash list, audit chain hash, signature metadata, timestamp metadata, or verification instructions change after export.
```

Expected detection:

- Export manifest hash mismatch.
- Evidence package hash mismatch.
- Audit chain hash mismatch.
- Signature metadata hash mismatch.
- Timestamp metadata hash mismatch.
- Verification instructions hash mismatch.

Validated record:

| Field | Value |
| --- | --- |
| Export Package ID | `reg-export-package-20260603-001` |
| Audit Package ID | `reg-audit-package-20260603-001` |
| Verification Package ID | `reg-verification-package-20260603-001` |
| Signature Metadata ID | `reg-signature-metadata-20260603-001` |
| Timestamp Metadata ID | `reg-timestamp-metadata-20260603-001` |
| Verification Result | `FAILED` |
| Failure Reason | `EXPORT_PACKAGE_HASH_MISMATCH` |

Required outcome:

```text
Decision = BLOCKED
Evidence Status = INVALID
Fail-Closed Status = true
```

## Scenario 7: Missing Evidence Package Rejected

Missing evidence action:

```text
Evidence package is absent from the regulator export package or cannot be resolved from the export manifest.
```

Expected detection:

- Evidence Package ID missing.
- Evidence package hash missing.
- Audit chain cannot reconstruct the decision from evidence.
- Verification package cannot complete independent verification.

Validated record:

| Field | Value |
| --- | --- |
| Export Package ID | `reg-export-package-20260603-001` |
| Audit Package ID | `reg-audit-package-20260603-001` |
| Verification Package ID | `reg-verification-package-20260603-001` |
| Signature Metadata ID | `reg-signature-metadata-20260603-001` |
| Timestamp Metadata ID | `reg-timestamp-metadata-20260603-001` |
| Verification Result | `FAILED` |
| Failure Reason | `EVIDENCE_PACKAGE_MISSING` |

Required outcome:

```text
Decision = BLOCKED
Evidence Status = INVALID
Fail-Closed Status = true
```

## Reproducibility Requirements

The export package is reproducible only when:

- Export Package ID resolves to the export manifest.
- Audit Package ID resolves to the audit chain.
- Verification Package ID resolves to verification instructions.
- Signature Metadata ID resolves to signature verification metadata.
- Timestamp Metadata ID resolves to timestamp verification metadata.
- Evidence package hash matches the export manifest.
- Audit chain hash matches the export manifest.
- Signature metadata hash matches the export manifest.
- Timestamp metadata hash matches the export manifest.
- Verification instructions hash matches the export manifest.

If any relationship is missing or hash-mismatched:

```text
Decision = BLOCKED
Failure Reason = REGULATOR_EXPORT_NOT_REPRODUCIBLE
```

## Regulator Export Safety Requirements

Regulator-facing export artifacts must not include:

- Credentials.
- Provider secrets.
- Private keys.
- Raw approvals.
- Raw regulator exports.
- Unredacted sensitive payloads.

If prohibited material is present:

```text
Decision = BLOCKED
Evidence Status = INVALID
Failure Reason = EXPORT_CONTAINS_PROHIBITED_MATERIAL
```

## Validation Matrix

| Scenario | Verification Result | Failure Reason | Required outcome |
| --- | --- | --- | --- |
| Evidence package exported | VERIFIED | Information not provided | Export valid |
| Audit chain exported | VERIFIED | Information not provided | Export valid |
| Signature metadata exported | VERIFIED | Information not provided | Export valid |
| Timestamp metadata exported | VERIFIED | Information not provided | Export valid |
| Verification instructions included | VERIFIED | Information not provided | Independent verification possible |
| Tampered package | FAILED | EXPORT_PACKAGE_HASH_MISMATCH | BLOCKED |
| Missing evidence package | FAILED | EVIDENCE_PACKAGE_MISSING | BLOCKED |

## Final Pilot Decision

Expected valid outcome:

```text
Independent Verification = POSSIBLE
Export Package = REPRODUCIBLE
Audit Export = VERIFIED
```

Required fail-closed outcome when evidence is missing, tampered, unverifiable, or unsafe:

```text
Decision = BLOCKED
Evidence Status = INVALID
Fail-Closed Status = true
```
