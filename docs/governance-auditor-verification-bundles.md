# Governance Auditor Verification Bundles

USBAY auditor verification bundles provide a deterministic, hash-only package for offline audit review. They bind a Merkle checkpoint, an inclusion proof summary, and a consistency proof summary without exporting raw governance payloads.

## Portable Audit Bundle Lifecycle

The bundle is created from already verified governance evidence:

- a Merkle checkpoint
- a Merkle inclusion proof for the audited evidence entry
- a Merkle consistency proof showing checkpoint continuity
- an explicit verification scope
- retention and governance module metadata

The canonical bundle payload is hashed into `bundle_id`. Any mutation to checkpoint IDs, roots, proof summaries, scope, timestamp, or retention metadata changes the bundle hash and fails verification.

## Offline Verification Model

Offline verification checks:

- bundle hash continuity
- checkpoint ID and Merkle root binding
- evidence-chain head hash consistency
- inclusion summary binding to the checkpoint
- consistency summary binding to the current checkpoint
- explicit verification scope
- redacted diagnostics

Verification fails closed on missing evidence, replayed bundle IDs, malformed scope, hash mismatch, or unsafe diagnostics.

## Proof-Summary Format

The bundle stores summaries only. It includes checkpoint IDs, Merkle roots, chain-head hashes, valid flags, and error code lists. It intentionally excludes raw evidence payloads, approval contents, private keys, secrets, and runtime-only material.

## Future External Auditor Portal Path

This module is local-only and has no blockchain or external transparency-log dependency. Future auditor portals can ingest the same bundle format and optionally request full proof artifacts or external witness anchors without changing the hash-only bundle contract.
