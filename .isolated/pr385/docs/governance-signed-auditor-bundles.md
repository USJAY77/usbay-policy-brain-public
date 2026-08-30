# Governance Signed Auditor Bundles

Signed auditor bundle envelopes authenticate portable USBAY auditor verification bundles without exposing raw governance payloads.

## Signed Bundle Lifecycle

A signed envelope is created from an already verified auditor bundle. The envelope stores:

- auditor bundle ID
- canonical auditor bundle hash
- Ed25519 signature metadata
- trusted signer key fingerprint
- signing timestamp
- verification scope
- retention label
- governance module versions

Private signing keys are supplied only at runtime and are never written to the repository or exported envelope.

## Canonical Bundle Hashing

The auditor bundle is serialized as deterministic JSON and hashed with SHA256. The signed envelope also has a deterministic `signed_bundle_id` derived from canonical envelope metadata before the signature is attached.

Verification recomputes both hashes and fails closed on any mismatch.

## Signer Trust Model

Envelope verification requires a trust policy containing an allowed signer ID, public key PEM, canonical DER public-key fingerprint, and validity window. Revoked, expired, unknown, or mismatched signer fingerprints are rejected.

The envelope stores no private key material and no raw approval contents.

## Future RFC3161 Timestamp Attachment Path

The local `signed_at_utc` field is deterministic metadata only. Future RFC3161 integration can timestamp the `signed_bundle_id` or canonical envelope hash as an external proof without changing the envelope’s core signature model.

## Future External Auditor Verification Path

External auditor tooling can verify the envelope with the auditor bundle file and public trust policy. Future auditor portals may add RFC3161, WORM, or transparency-log evidence around the same canonical envelope hash.
