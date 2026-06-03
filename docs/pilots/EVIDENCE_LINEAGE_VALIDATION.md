# Evidence Lineage and Audit Export Chain Validation

Purpose: validate the complete USBAY audit evidence chain from request creation through export verification.

Runtime impact: none.

Credentials committed: none.

Private keys committed: none.

Provider secrets committed: none.

Certification claim: none.

Blocker status change: none.

Default decision: BLOCKED.

Required governance rule:

- Evidence before claims.
- USBAY decides.
- Humans approve.
- Fail closed by default.

## Validation Scope

This pilot validates the audit evidence chain for a single governed request:

1. Request created.
2. Evidence package created.
3. Review recorded.
4. Signature generated.
5. Timestamp generated.
6. WORM archive recorded.
7. Export bundle generated.
8. Export verification completed.

The validation is documentation-only. It does not create provider resources, store credentials, store private keys, modify runtime enforcement, modify policy enforcement, change blocker status, or make certification claims.

## Required Evidence Identifiers

Every validated chain must include these identifiers:

| Evidence field | Required value |
| --- | --- |
| Request ID | Present |
| Evidence ID | Present |
| Review ID | Present |
| Decision ID | Present |
| Signature ID | Present |
| Timestamp ID | Present |
| Archive ID | Present |
| Export Bundle ID | Present |
| Verification ID | Present |

If any identifier is missing:

```text
Decision = BLOCKED
```

## Validated Lineage Record

The validated pilot chain uses deterministic, non-secret identifiers. No raw approval content, credentials, private keys, provider secrets, or raw regulator exports are included.

| Field | Value |
| --- | --- |
| Request ID | `request-lineage-20260603-001` |
| Evidence ID | `evidence-lineage-20260603-001` |
| Review ID | `review-lineage-20260603-001` |
| Decision ID | `decision-lineage-20260603-001` |
| Signature ID | `signature-lineage-20260603-001` |
| Timestamp ID | `timestamp-lineage-20260603-001` |
| Archive ID | `archive-lineage-20260603-001` |
| Export Bundle ID | `export-bundle-lineage-20260603-001` |
| Verification ID | `verification-lineage-20260603-001` |
| Evidence Source | `USBAY governance control-plane audit evidence references` |
| Human Review Status | `RECORDED` |
| Export Verification Status | `VERIFIED` |
| Fail-Closed Status | `false` |

Validation result:

```text
APPROVED
```

The approved lineage result is valid only when every required identifier exists, every link is reproducible, and the export verification result confirms bundle integrity.

## Chain Validation Steps

### 1. Request Created

Required evidence:

- Request ID.
- Request actor reference.
- Request device or system identity.
- Request timestamp.
- Request scope.

Validated record:

```text
Request ID: request-lineage-20260603-001
Status: PRESENT
```

Fail-closed condition:

```text
Decision = BLOCKED
Reason = REQUEST_MISSING
```

### 2. Evidence Package Created

Required evidence:

- Evidence ID.
- Evidence package hash.
- Evidence source.
- Chain-of-custody reference.
- Scope boundary.

Validated record:

```text
Evidence ID: evidence-lineage-20260603-001
Status: PRESENT
```

Fail-closed condition:

```text
Decision = BLOCKED
Reason = EVIDENCE_PACKAGE_MISSING
```

### 3. Review Recorded

Required evidence:

- Review ID.
- Human reviewer reference.
- Review timestamp.
- Reviewed evidence reference.
- Review decision.

Validated record:

```text
Review ID: review-lineage-20260603-001
Status: PRESENT
```

Human approval does not replace evidence. Human review is valid only when linked to the evidence package and decision record.

Fail-closed condition:

```text
Decision = BLOCKED
Reason = HUMAN_REVIEW_MISSING
```

### 4. Signature Generated

Required evidence:

- Signature ID.
- Signed artifact reference.
- Signed artifact SHA256.
- Public key reference.
- Signature validation status.

Validated record:

```text
Signature ID: signature-lineage-20260603-001
Status: PRESENT
```

Private keys must not be stored in the repository or audit output.

Fail-closed condition:

```text
Decision = BLOCKED
Reason = SIGNATURE_MISSING_OR_INVALID
```

### 5. Timestamp Generated

Required evidence:

- Timestamp ID.
- Timestamp subject reference.
- Timestamp subject SHA256.
- Trusted timestamp token hash or timestamp evidence reference.
- Timestamp validation status.

Validated record:

```text
Timestamp ID: timestamp-lineage-20260603-001
Status: PRESENT
```

Fail-closed condition:

```text
Decision = BLOCKED
Reason = TIMESTAMP_MISSING_OR_INVALID
```

### 6. WORM Archive Recorded

Required evidence:

- Archive ID.
- Archive object reference.
- Archive manifest hash.
- Retention evidence reference.
- Immutability evidence reference.
- Archive validation status.

Validated record:

```text
Archive ID: archive-lineage-20260603-001
Status: PRESENT
```

This pilot records lineage requirements only. It does not claim external WORM provider verification.

Fail-closed condition:

```text
Decision = BLOCKED
Reason = WORM_ARCHIVE_MISSING_OR_UNVERIFIED
```

### 7. Export Bundle Generated

Required evidence:

- Export Bundle ID.
- Export manifest hash.
- Evidence hash list.
- Chain-of-custody record.
- Review decision reference.
- Signature reference.
- Timestamp reference.
- Archive reference.

Validated record:

```text
Export Bundle ID: export-bundle-lineage-20260603-001
Status: PRESENT
```

Fail-closed condition:

```text
Decision = BLOCKED
Reason = EXPORT_BUNDLE_MISSING
```

### 8. Export Verification Completed

Required evidence:

- Verification ID.
- Export bundle reference.
- Verification timestamp.
- Verification result.
- Missing artifact check result.
- Hash verification result.
- Tamper detection result.

Validated record:

```text
Verification ID: verification-lineage-20260603-001
Status: VERIFIED
```

Fail-closed condition:

```text
Decision = BLOCKED
Reason = EXPORT_VERIFICATION_FAILED
```

## Reproducibility Requirements

Evidence lineage is reproducible only when:

- Request ID maps to the evidence package.
- Evidence ID maps to the review record.
- Review ID maps to the decision record.
- Decision ID maps to the signature record.
- Signature ID maps to the timestamp record.
- Timestamp ID maps to the archive record.
- Archive ID maps to the export bundle.
- Export Bundle ID maps to the verification record.
- Verification ID maps to the final audit export result.

If any relationship is missing, broken, duplicated, or hash-mismatched:

```text
Decision = BLOCKED
Reason = LINEAGE_INCOMPLETE
```

## Export Verification Requirements

Audit export verifies successfully only when:

- Export manifest exists.
- Evidence hashes match.
- Chain-of-custody record exists.
- Validation result exists.
- Review decision exists.
- Signature reference exists.
- Timestamp reference exists.
- Archive reference exists.
- Verification result is recorded.
- No credentials, private keys, raw approvals, or provider secrets are present in the export output.

If audit export cannot be verified:

```text
Decision = BLOCKED
Reason = AUDIT_EXPORT_UNVERIFIED
```

## Fail-Closed Matrix

| Missing or failed control | Required outcome |
| --- | --- |
| Request missing | BLOCKED |
| Evidence package missing | BLOCKED |
| Review missing | BLOCKED |
| Decision missing | BLOCKED |
| Signature missing or invalid | BLOCKED |
| Timestamp missing or invalid | BLOCKED |
| WORM archive missing or unverified | BLOCKED |
| Export bundle missing | BLOCKED |
| Export verification missing or failed | BLOCKED |
| Lineage relationship missing | BLOCKED |
| Hash mismatch detected | BLOCKED |
| Credentials or secrets present in audit output | BLOCKED |
| Raw approval content present in audit output | BLOCKED |

## Governance Boundary

USBAY remains the enforcement authority for the evidence chain.

Euria or any external assistant may analyze evidence gaps, summarize validation status, and prepare review materials. Euria may not approve, execute, modify policy, bypass review, alter audit records, close blockers, issue certification, or override USBAY enforcement.

Human review is required but does not replace cryptographic evidence, timestamp evidence, WORM archive evidence, export verification, or lineage continuity.

## Final Pilot Decision

The complete chain is valid only when every required artifact and relationship exists and export verification completes successfully.

Validated pilot outcome:

```text
Decision = APPROVED
Export Verification = VERIFIED
Fail-Closed Status = false
```

Required outcome if any evidence item is missing or unverifiable:

```text
Decision = BLOCKED
Fail-Closed Status = true
```
