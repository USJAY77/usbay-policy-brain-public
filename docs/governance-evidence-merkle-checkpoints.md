# Governance Evidence Merkle Checkpoints

USBAY Merkle checkpoints batch evidence-chain entries into deterministic local roots. They let auditors verify a range of append-only governance evidence efficiently without exposing raw proof bundles, request payloads, approval contents, or secrets.

## Checkpoint Lifecycle

A checkpoint is created from a verified evidence chain and a requested inclusive chain range. The checkpoint records:

- checkpoint ID
- chain start and end positions
- evidence-chain leaf hashes
- Merkle root
- evidence-chain head hash
- UTC timestamp
- governance module versions
- retention policy label

The checkpoint ID is derived from the canonical checkpoint payload. Verification recomputes the leaf root, validates range semantics, and optionally binds the checkpoint to an evidence chain head.

## Inclusion Proof Model

The initial model stores the checkpoint leaf hashes directly. Future inclusion-proof tooling can derive compact sibling paths from the same deterministic pairing rule. When the leaf count is odd, the last leaf is duplicated for that level.

## Chain-Head Binding

Checkpoints bind to the latest evidence-chain head hash at creation time. Verification with the source chain fails closed if the checkpoint range leaves or head hash differ from the provided chain.

## Future Transparency-Log Anchoring Path

The Merkle root can be submitted to future transparency logs, witness networks, or RFC3161/WORM export flows. Those future integrations must submit only hashes and redacted metadata, never raw governance payloads or private material.
