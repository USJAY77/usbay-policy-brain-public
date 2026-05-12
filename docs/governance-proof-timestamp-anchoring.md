# Governance Proof Timestamp Anchoring

USBAY proof timestamp anchors bind a verified policy proof bundle to a deterministic local UTC timestamp. This is a local anchoring layer only: it does not call an external TSA, does not produce RFC3161 tokens, and does not write to WORM storage. It prepares proof bundles for those stronger anchoring controls without introducing network dependencies or secret exposure.

## Timestamp Lifecycle

The anchor module verifies the proof bundle first. If the proof bundle is invalid, contains unsafe diagnostics, or cannot prove runtime parity, anchoring fails closed. A valid anchor includes:

- proof bundle hash
- UTC timestamp
- canonical timestamp payload
- governance module versions
- validation status
- anchor hash

Verification recomputes the canonical payload and anchor hash. When the original proof bundle is supplied, verification also checks that the anchor hash references that exact bundle, preventing replay across different proof bundles.

## Local Timestamp Limitations

Local timestamps prove deterministic runtime recording, not independent time authority. They do not prove external chronology, trusted clock provenance, or append-only storage durability. Operators must treat local anchors as pre-TSA evidence and not as a substitute for RFC3161, transparency log, or WORM evidence.

## Future Upgrade Path

The timestamp payload is intentionally canonical and hash based so it can be submitted later to:

- RFC3161 timestamp authority validation
- WORM archive manifests
- transparency log anchoring
- distributed chronology consensus

All future upgrades must preserve fail-closed verification, redacted diagnostics, and no raw payload export.
