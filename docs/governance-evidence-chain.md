# Governance Evidence Chain

USBAY evidence chains provide deterministic append-only continuity for governance proof bundles, local timestamp anchors, RFC3161 preflight requests, and WORM evidence manifests. The chain is local and hash based. It does not depend on blockchains, distributed networks, or external transparency logs.

## Append-Only Evidence Lifecycle

Each appended entry records:

- previous chain hash
- current manifest hash
- proof bundle hash
- timestamp anchor hash
- RFC3161 preflight request digest
- WORM manifest hash
- chain position
- UTC timestamp
- governance module versions
- retention policy label

Position zero uses a fixed genesis hash. Every later entry must reference the previous entry's `current_manifest_hash`. Verification recomputes each entry hash and the full chain hash.

## Replay Detection Model

The verifier rejects duplicate entry hashes and duplicate WORM manifest hashes. This prevents a previously archived evidence unit from being replayed as a new chronological event inside the same chain.

## Chronology Continuity Guarantees

The evidence chain proves local append order and deterministic hash continuity. It does not prove external time, independent witness consensus, or immutable storage durability. Those guarantees must come from future timestamp, transparency, and WORM integrations.

## Future Merkle Anchoring Path

The chain hash can be used as a Merkle leaf or batch root input in a future anchoring layer. That future layer should preserve the current entry format and fail closed on any mismatch between chain entry hashes and external roots.

## Future Transparency-Log Integration

Future transparency logs should consume only hashes and redacted metadata from the evidence chain. Raw proof bundles, request contexts, approval contents, private keys, and secrets must never be uploaded or logged.
