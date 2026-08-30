# Governance Evidence Merkle Inclusion Proofs

USBAY Merkle inclusion proofs let auditors verify a single governance evidence-chain entry against a Merkle checkpoint without replaying the full chain or exposing raw payloads.

## Inclusion Proof Lifecycle

An inclusion proof is generated from a verified Merkle checkpoint and a leaf index. The proof records:

- checkpoint ID
- target leaf hash
- leaf index
- sibling path
- Merkle root
- evidence-chain head hash
- checkpoint range
- governance module versions

Verification recomputes the root from the leaf and sibling path, then optionally checks that the proof binds to a supplied checkpoint.

## Leaf-To-Root Verification Model

Each sibling step includes a direction and a hash. `left` means the sibling hash is prepended before hashing. `right` means it is appended. Odd leaf counts duplicate the final leaf at that level, matching checkpoint generation.

## Checkpoint Binding

When a checkpoint is supplied, verification confirms the checkpoint ID, Merkle root, chain head hash, leaf index, and leaf hash all match. Any mismatch fails closed.

## Future External Auditor Verification Path

The proof format is portable and hash-only. Future auditor tooling can verify inclusion proofs offline using the checkpoint and proof JSON without receiving raw governance payloads, request contexts, approval material, or secrets.
