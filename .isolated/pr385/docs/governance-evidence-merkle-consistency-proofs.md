# Governance Evidence Merkle Consistency Proofs

USBAY Merkle consistency proofs let auditors verify that one governance Merkle checkpoint is an append-only extension of an earlier checkpoint without replaying the full evidence chain.

## Checkpoint Lifecycle

Each proof binds a previous checkpoint to a current checkpoint using only hash material:

- previous checkpoint ID and Merkle root
- current checkpoint ID and Merkle root
- previous and current chain end positions
- hash-only consistency path
- current evidence chain head hash
- governance module version metadata

Raw governance payloads, private keys, approval contents, secrets, and runtime material are never included.

## Append-Only Model

The consistency path contains the previous checkpoint leaf hashes and the appended leaf hashes. Verification recomputes:

- the previous Merkle root from the previous leaves
- the current Merkle root from previous leaves plus appended leaves
- monotonic range continuity from previous chain end to current chain end

If roots, ranges, checkpoint IDs, or hash paths diverge, verification fails closed.

## Tree-Head Continuity

When checkpoint files are supplied, verification also binds the proof back to both checkpoint records. The current checkpoint evidence-chain head is treated as the authoritative tree head for the consistency proof.

Replay is rejected when a proof attempts to reuse the same checkpoint pair or does not include an append-only extension.

## Future Transparency-Log Witness Path

This module is local-only. It does not write to a blockchain or external transparency log. Future integration can anchor the consistency proof hash and checkpoint IDs with external witnesses while keeping the same redacted, hash-only proof format.
