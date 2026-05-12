# Governance Signed Bundle LTV Evidence

Long-term validation evidence preserves auditor verifiability for timestamped signed governance bundles after TSA certificates, revocation endpoints, or local runtime state change.

## LTV Evidence Lifecycle

An LTV evidence record is created from a signed bundle timestamp attachment. It binds:

- timestamp attachment ID
- signed bundle ID
- timestamp token hash
- TSA certificate fingerprint
- TSA certificate-chain fingerprints
- trust-anchor fingerprint
- revocation evidence metadata
- validation policy ID
- retention label
- governance module versions

Only fingerprints and metadata are exported. Raw certificates, private keys, approval contents, and raw governance payloads are intentionally excluded.

## TSA Certificate-Chain Model

The TSA signing certificate fingerprint and ordered certificate-chain fingerprints are recorded as deterministic SHA256 values. Verification requires a non-empty chain and requires the trust-anchor fingerprint to appear in the chain.

## Revocation Evidence Model

The revocation evidence type identifies the source category, such as `ocsp`, `crl`, `ocsp_crl`, or `offline_mock`. The revocation evidence hash binds the detached revocation material without exporting raw OCSP or CRL payloads.

## Trust-Anchor Governance Model

The trust anchor is represented by fingerprint only. This keeps LTV evidence portable and redacted while allowing future auditor tools to compare the fingerprint against an independently governed TSA trust store.

## Future External TSA/OCSP/CRL Integration Path

This module is local and deterministic. Future integration can attach real RFC3161 tokens, OCSP responses, CRLs, and TSA certificate chains as detached artifacts while preserving the same hash-bound LTV evidence record.
