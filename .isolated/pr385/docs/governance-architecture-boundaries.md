# USBAY Governance Architecture Boundaries

This document describes the phase 1 and phase 2 governance stabilization
boundaries for CI evidence, trust policy, timestamp, chronology, dependency
validation, and validation telemetry controls.

## Boundary Principles

- Fail closed on malformed, missing, unsigned, stale, or ambiguous governance data.
- Keep canonical Ed25519 public key fingerprints derived from SubjectPublicKeyInfo DER bytes only.
- Preserve append-only audit records for trust-policy and chronology evidence.
- Do not log private keys, raw secrets, approval contents, raw nonces, or private signing material.
- Keep structural validation separate from cryptographic verification.
- Make dependency drift observable and fail closed before runtime enforcement.

## Governance Domains

### Evidence

Module: `governance.evidence`

The evidence boundary defines the `EvidenceManifest` interface and validates CI
evidence manifest shape before hash-chain and signature verification. The
evidence engine in `scripts/generate_ci_evidence_manifest.py` still performs
file hash checks, chain continuity checks, and signature verification.

### Trust Policy Validation

Module: `governance.trust_policy`

The trust-policy boundary validates public signer entries, signer IDs,
fingerprints, public key PEM presence, and validity windows. The trust-policy
governance verifier then enforces signature validity, signer authority,
revocation, public-key fingerprint matching, and append-only audit continuity.

### Timestamp Verification

Module: `governance.timestamping`

The timestamp boundary defines `TimestampVerificationResult` and validates that
timestamp verification results contain deterministic validity, message imprint,
timestamp hash, and failure metadata. The RFC3161 proof verifier remains
responsible for token integrity, continuity, replay detection, and TSA policy
validation.

### Chronology

Module: `governance.chronology`

The chronology boundary defines `ChronologyConsensus` and
`ChronologyConsensusRecord`. It validates consensus shape, authority result
presence, quorum fields, skew policy, chain head, and ALLOW/DENY result values.
The chronology verifier remains responsible for consensus continuity,
multi-authority timestamp agreement, quorum enforcement, and append-only audit
records.

### Dependency Validation

Module: `governance.dependencies`

The dependency boundary statically inspects governance modules and produces a
deterministic graph hash. It validates that evidence, chronology, timestamping,
and trust-policy modules depend only on `governance.interfaces`. It rejects
circular imports, forbidden cross-domain imports, and coupling from governance
boundary modules into runtime, audit, gateway, security, or simulation code.

### Validation Telemetry

Module: `governance.telemetry`

The telemetry boundary wraps validation functions and records aggregate,
audit-safe metrics: latency in nanoseconds, domain, operation, validity,
failure count, and artifact counts. Telemetry never serializes payload contents
and never logs private key material or raw evidence.

## Trust Flow

1. CI runtime derives an Ed25519 public key from `USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM`.
2. The public key is normalized to PEM and converted to canonical DER.
3. The DER SHA256 fingerprint is compared with `governance/ci_evidence_trust_policy.json`.
4. Trust-policy shape, signature, authority, revocation, and audit continuity are verified.
5. Evidence signing is denied if signer trust is absent or ambiguous.

## Evidence Verification Flow

1. Evidence manifest shape is validated at the evidence boundary.
2. File hashes are recalculated from repository/workflow artifacts.
3. Hash-chain continuity is validated from `GENESIS` to `chain_head`.
4. Signature metadata is validated against the trusted public key.
5. Ed25519 signature verification uses canonical public key normalization.

## Chronology Validation Flow

1. Timestamp targets are hashed.
2. RFC3161-compatible timestamp proofs are generated and verified.
3. Chronology consensus shape is validated at the chronology boundary.
4. Authority membership, quorum, timestamp freshness, continuity, replay, and audit records are verified.
5. Any disagreement, missing quorum, malformed record, or stale proof fails closed.

## Dependency Validation Flow

1. Source text for explicit governance boundary modules is parsed with Python AST.
2. Imports are reduced to deterministic governance-domain edges.
3. Allowed edges are compared with the boundary allowlist.
4. Cycles, forbidden domain imports, and runtime coupling are collected as
   fail-closed failure codes.
5. Production-readiness validation rejects the repository if dependency drift is
   present.

## Telemetry Flow

1. A boundary validator is invoked through `measure_governance_validation()`.
2. The underlying validator result remains the source of truth.
3. Validator exceptions become invalid validation results.
4. Aggregate latency and artifact counts are attached to evidence, trust-policy,
   timestamp, or chronology summaries.
5. Telemetry is safe for CI logs because it contains no payload bodies, secrets,
   raw nonces, approval material, or private keys.
