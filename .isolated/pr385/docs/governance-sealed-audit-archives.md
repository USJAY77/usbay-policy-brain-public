# Governance Sealed Audit Archives

USBAY sealed audit archives provide a deterministic outer package record for external governance verification. The archive binds an evidence chain, signed auditor bundle, timestamp attachment, LTV evidence, revocation preflight, and revocation response verification by canonical hashes and ordered manifest entries.

## Lifecycle

1. Verify evidence-chain continuity.
2. Verify signed bundle timestamp attachment.
3. Verify LTV evidence.
4. Verify OCSP/CRL revocation preflight.
5. Verify OCSP/CRL revocation response metadata.
6. Generate ordered manifest entries and seal the archive root hash.

The archive record is hash-only. It does not export raw governance payloads, raw OCSP/CRL data, raw certificates, private keys, or approval contents.

## Canonical Archive Hashing

Every artifact is hashed with deterministic canonical JSON. Manifest entries bind artifact type, canonical file hash, verification scope, append-only position, and replay-binding hash. The archive manifest hash covers the ordered entry list, and the archive root hash covers the ordered manifest entry hashes.

## Append-Only Ordering

Archive evidence order is fixed:

1. evidence chain
2. signed bundle
3. timestamp attachment
4. LTV evidence
5. revocation preflight
6. revocation response

Reordered, missing, duplicated, or position-shifted evidence fails closed.

## Replay Binding Model

Each manifest entry includes a replay-binding hash derived from its artifact type, canonical hash, verification scope, append-only position, and the previous entry replay-binding hash. This makes archive ordering replay-safe without requiring a blockchain or external transparency log.

## Future Paths

Future immutable archive storage should store this sealed archive record in WORM storage and preserve the same canonical hashes. A future regulator export profile can wrap this archive with jurisdiction-specific metadata while keeping raw payloads out of the portable audit surface.
