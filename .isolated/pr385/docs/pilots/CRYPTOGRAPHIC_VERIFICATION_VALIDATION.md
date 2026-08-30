# Cryptographic Evidence Verification Validation

Purpose: validate that USBAY evidence signatures and timestamps can be independently verified, and that modified evidence, modified signatures, and modified timestamps are rejected fail-closed.

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

This hardening pilot validates:

1. Signature generated.
2. Signature verified.
3. Timestamp generated.
4. Timestamp verified.
5. Export bundle verified.
6. Tampered signature rejected.
7. Tampered timestamp rejected.

Every validation record must include:

- Request ID.
- Decision ID.
- Signature ID.
- Timestamp ID.
- Verification Result.
- Failure Reason.

This pilot is documentation-only. It does not generate real keys, commit private keys, store credentials, create provider resources, modify runtime behavior, modify gateway logic, modify policy enforcement, make certification claims, or change blocker status.

## Baseline Verification Record

The baseline uses deterministic, non-secret identifiers and hash references. No raw evidence payload, raw approval, credential, provider secret, private key, or raw regulator export is included.

| Field | Value |
| --- | --- |
| Request ID | `request-crypto-20260603-001` |
| Decision ID | `decision-crypto-20260603-001` |
| Signature ID | `signature-crypto-20260603-001` |
| Timestamp ID | `timestamp-crypto-20260603-001` |
| Export Bundle ID | `export-bundle-crypto-20260603-001` |
| Signature Verification ID | `signature-verification-crypto-20260603-001` |
| Timestamp Verification ID | `timestamp-verification-crypto-20260603-001` |
| Export Verification ID | `export-verification-crypto-20260603-001` |
| Evidence Hash | `sha256:baseline-crypto-evidence-hash-reference` |
| Signed Artifact Hash | `sha256:baseline-crypto-signed-artifact-hash-reference` |
| Timestamp Subject Hash | `sha256:baseline-crypto-timestamp-subject-hash-reference` |
| Export Bundle Hash | `sha256:baseline-crypto-export-bundle-hash-reference` |

Baseline verification may pass only when the signature validates against the signed artifact, the timestamp validates against the timestamp subject, and the export bundle validates against the expected manifest hash.

## Scenario 1: Signature Generated

Required evidence:

- Request ID.
- Decision ID.
- Signature ID.
- Signed artifact reference.
- Signed artifact SHA256.
- Public key reference.
- Signature algorithm reference.
- Signature generation timestamp.

Validated record:

| Field | Value |
| --- | --- |
| Request ID | `request-crypto-20260603-001` |
| Decision ID | `decision-crypto-20260603-001` |
| Signature ID | `signature-crypto-20260603-001` |
| Timestamp ID | `timestamp-crypto-20260603-001` |
| Verification Result | `PENDING_VERIFICATION` |
| Failure Reason | `Information not provided` |

Fail-closed rule:

```text
Decision = BLOCKED
Reason = SIGNATURE_NOT_VERIFIED
```

until signature verification succeeds.

## Scenario 2: Signature Verified

Required evidence:

- Signature ID.
- Signature verification ID.
- Signed artifact SHA256.
- Public key reference.
- Verification algorithm reference.
- Verification timestamp.
- Verification result.

Validated record:

| Field | Value |
| --- | --- |
| Request ID | `request-crypto-20260603-001` |
| Decision ID | `decision-crypto-20260603-001` |
| Signature ID | `signature-crypto-20260603-001` |
| Timestamp ID | `timestamp-crypto-20260603-001` |
| Verification Result | `VERIFIED` |
| Failure Reason | `Information not provided` |

Expected outcome:

```text
Signature Verification = VERIFIED
Evidence Status = VALID
```

The verified result is valid only for the exact signed artifact hash recorded in the evidence chain.

## Scenario 3: Timestamp Generated

Required evidence:

- Request ID.
- Decision ID.
- Timestamp ID.
- Timestamp subject reference.
- Timestamp subject SHA256.
- Timestamp token hash or timestamp evidence reference.
- Timestamp generation time.

Validated record:

| Field | Value |
| --- | --- |
| Request ID | `request-crypto-20260603-001` |
| Decision ID | `decision-crypto-20260603-001` |
| Signature ID | `signature-crypto-20260603-001` |
| Timestamp ID | `timestamp-crypto-20260603-001` |
| Verification Result | `PENDING_VERIFICATION` |
| Failure Reason | `Information not provided` |

Fail-closed rule:

```text
Decision = BLOCKED
Reason = TIMESTAMP_NOT_VERIFIED
```

until timestamp verification succeeds.

## Scenario 4: Timestamp Verified

Required evidence:

- Timestamp ID.
- Timestamp verification ID.
- Timestamp subject SHA256.
- Timestamp token hash or timestamp evidence reference.
- Verification timestamp.
- Verification result.

Validated record:

| Field | Value |
| --- | --- |
| Request ID | `request-crypto-20260603-001` |
| Decision ID | `decision-crypto-20260603-001` |
| Signature ID | `signature-crypto-20260603-001` |
| Timestamp ID | `timestamp-crypto-20260603-001` |
| Verification Result | `VERIFIED` |
| Failure Reason | `Information not provided` |

Expected outcome:

```text
Timestamp Verification = VERIFIED
Evidence Status = VALID
```

The verified result is valid only for the exact timestamp subject hash recorded in the evidence chain.

## Scenario 5: Export Bundle Verified

Required evidence:

- Export bundle ID.
- Export manifest hash.
- Signature verification reference.
- Timestamp verification reference.
- Evidence hash list.
- Chain-of-custody reference.
- Export verification result.

Validated record:

| Field | Value |
| --- | --- |
| Request ID | `request-crypto-20260603-001` |
| Decision ID | `decision-crypto-20260603-001` |
| Signature ID | `signature-crypto-20260603-001` |
| Timestamp ID | `timestamp-crypto-20260603-001` |
| Verification Result | `VERIFIED` |
| Failure Reason | `Information not provided` |

Expected outcome:

```text
Export Bundle Verification = VERIFIED
Evidence Status = VALID
```

The export bundle verifies successfully only when all included signature, timestamp, evidence, and manifest hashes match the recorded audit chain.

## Scenario 6: Tampered Signature Rejected

Tamper action:

```text
Signature value, signature metadata, signed artifact reference, public key reference, or signature hash changes after signature generation.
```

Expected detection:

- Signature verification fails.
- Signed artifact hash no longer validates against the signature record.
- Timestamp reference remains bound to the original signed artifact.
- Export bundle signature reference no longer matches the tampered signature.

Validated record:

| Field | Value |
| --- | --- |
| Request ID | `request-crypto-20260603-001` |
| Decision ID | `decision-crypto-20260603-001` |
| Signature ID | `signature-crypto-20260603-001` |
| Timestamp ID | `timestamp-crypto-20260603-001` |
| Verification Result | `FAILED` |
| Failure Reason | `SIGNATURE_INVALID` |

Required outcome:

```text
Decision = BLOCKED
Evidence Status = INVALID
Fail-Closed Status = true
```

## Scenario 7: Tampered Timestamp Rejected

Tamper action:

```text
Timestamp token hash, timestamp subject reference, timestamp value, timestamp authority metadata, or timestamp chain reference changes after timestamp generation.
```

Expected detection:

- Timestamp verification fails.
- Timestamp subject hash no longer matches the signed artifact hash.
- Export bundle timestamp reference no longer matches the tampered timestamp.
- Audit chain cannot prove continuity from signature to timestamp.

Validated record:

| Field | Value |
| --- | --- |
| Request ID | `request-crypto-20260603-001` |
| Decision ID | `decision-crypto-20260603-001` |
| Signature ID | `signature-crypto-20260603-001` |
| Timestamp ID | `timestamp-crypto-20260603-001` |
| Verification Result | `FAILED` |
| Failure Reason | `TIMESTAMP_INVALID` |

Required outcome:

```text
Decision = BLOCKED
Evidence Status = INVALID
Fail-Closed Status = true
```

## Modified Evidence Rejection

Modified evidence must be rejected even when signature and timestamp records still exist.

Expected detection:

- Evidence hash no longer matches the signed artifact hash.
- Signature verification fails against the modified evidence.
- Timestamp subject hash remains bound to the original evidence state.
- Export bundle verification fails.

Required outcome:

```text
Decision = BLOCKED
Evidence Status = INVALID
Failure Reason = EVIDENCE_HASH_MISMATCH
```

## Verification Matrix

| Scenario | Verification Result | Failure Reason | Required outcome |
| --- | --- | --- | --- |
| Signature generated but not verified | PENDING_VERIFICATION | SIGNATURE_NOT_VERIFIED | BLOCKED |
| Signature verified | VERIFIED | Information not provided | VALID |
| Timestamp generated but not verified | PENDING_VERIFICATION | TIMESTAMP_NOT_VERIFIED | BLOCKED |
| Timestamp verified | VERIFIED | Information not provided | VALID |
| Export bundle verified | VERIFIED | Information not provided | VALID |
| Modified evidence | FAILED | EVIDENCE_HASH_MISMATCH | BLOCKED |
| Tampered signature | FAILED | SIGNATURE_INVALID | BLOCKED |
| Tampered timestamp | FAILED | TIMESTAMP_INVALID | BLOCKED |

## Independent Verification Requirements

Independent verification requires:

- Public verification material only.
- No private keys.
- No credentials.
- No provider secrets.
- No raw approvals.
- Reproducible artifact hashes.
- Verifiable signature references.
- Verifiable timestamp references.
- Verifiable export bundle manifest.
- Deterministic failure reasons.

If independent verification cannot be reproduced:

```text
Decision = BLOCKED
Failure Reason = VERIFICATION_NOT_REPRODUCIBLE
```

## Final Hardening Decision

Valid evidence verifies successfully only when:

- Signature is generated and independently verified.
- Timestamp is generated and independently verified.
- Export bundle verification succeeds.
- Evidence hashes match the signed artifact.
- Timestamp subject matches the signed artifact.
- No prohibited material appears in exported artifacts.

Modified evidence, modified signatures, and modified timestamps must be rejected.

Required fail-closed outcome for any verification failure:

```text
Decision = BLOCKED
Evidence Status = INVALID
Fail-Closed Status = true
```
