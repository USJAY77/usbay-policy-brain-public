# Governance Signed Bundle Revocation Preflight

USBAY signed bundle LTV evidence now has a deterministic, local-only OCSP/CRL refresh preflight layer. The preflight record does not contact revocation services. It plans future refresh work by binding hash-only revocation source metadata to already verified signed bundle LTV evidence.

## Lifecycle

1. Verify signed bundle timestamp evidence.
2. Verify signed bundle LTV evidence, including TSA certificate-chain fingerprints, trust-anchor fingerprint, and revocation evidence metadata.
3. Create a revocation preflight record for either `OCSP` or `CRL`.
4. Bind the preflight to the LTV evidence ID, timestamp attachment ID, TSA certificate fingerprint, trust-anchor fingerprint, validation policy, and retention label.
5. Verify the preflight before any future live revocation refresh is attempted.

Verification fails closed if the LTV evidence is missing, certificate fingerprints are absent, source metadata is malformed, freshness bounds are invalid, hashes mismatch, replay is detected, or diagnostics contain unsafe material.

## Freshness Window Model

`expected_freshness_window_seconds` is a deterministic planning bound for future revocation refresh. It must be a positive integer and cannot exceed one year. This is not a live revocation status claim; it is an audit-safe preflight constraint that future OCSP/CRL refresh implementations must honor.

## Revocation Source Hashing

Preflight records store `revocation_source_uri_hash`, not raw OCSP or CRL URIs. The hash is a lowercase SHA256 hex digest. This prevents raw certificate distribution points or governance payload context from being exported while still allowing deterministic source continuity checks.

## Future Integration Path

The current layer intentionally performs no network calls and exports no raw certificates. Future live OCSP/CRL integration should consume this preflight record, fetch only through approved governance execution paths, attach the fetched response hash, and preserve fail-closed verification if response validation, freshness, or source continuity cannot be proven.
