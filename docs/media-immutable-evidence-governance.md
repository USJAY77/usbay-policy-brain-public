# USBAY Media Immutable Evidence Governance

This non-production scaffold makes the immutable evidence production gap explicit. It does not add WORM storage, blockchain, cloud ledger, RFC3161 integration, real signing, or production evidence sealing.

## Governed Gap

Production media governance requires immutable, timestamp-bound, signed, append-only evidence lineage. This scaffold models that requirement with references only.

## Fail-Closed Conditions

- Evidence bundle has no signature reference
- Chain hash reference is missing
- Storage is marked mutable
- Timestamp reference is missing
- Lineage gap is detected
- Replay occurs without an evidence anchor

## Demo Boundary

The manifest is reference-only and non-production. Humans must approve any real immutable storage, timestamp authority, signing authority, retention policy, and regulator export path before production use.
