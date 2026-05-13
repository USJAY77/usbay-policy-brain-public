# Governance Evidence Record Chains

USBAY evidence record chains provide deterministic renewable evidence records for sealed governance audit archives. The model is inspired by RFC4998 Evidence Record Syntax, but this implementation is local-only and does not call a live TSA yet.

## Evidence Record Lifecycle

1. Create a sealed audit archive.
2. Create the initial evidence record for the archive root hash.
3. Renew the evidence record when hash-age, retention policy, or future cryptographic transition policy requires it.
4. Verify the full append-only renewal chain before relying on archive continuity.

Each top-level chain mirrors the latest evidence record so external verifiers can quickly inspect the current archive timestamp state without replaying raw payloads.

## Archive Timestamp Renewal Model

Every renewal record includes the sealed archive ID, archive root hash, previous evidence record hash, renewal round, hash algorithm, renewal reason, timestamp, replay-binding hash, append-only position, governance module versions, and retention label. The archive timestamp chain hash is computed from the ordered renewal entry hashes.

## Append-Only Chronology Model

Renewal rounds and append-only positions must increase by exactly one. Each record must reference the previous evidence record hash, and every renewal manifest entry must bind the prior chain hash, archive root, timestamp continuity hash, replay binding, and append-only position. Reordering, removing, or rewriting renewals fails closed.

## Replay-Binding Model

The replay-binding hash links the sealed archive ID, archive root hash, previous evidence record hash, timestamp continuity hash, and append-only position. A reused evidence record ID or replay binding is rejected.

## Future Compatibility Paths

Future RFC4998 compatibility can wrap these deterministic renewal records with external timestamp tokens. Future immutable archive renewal can store each renewal in WORM storage. Future post-quantum renewal can add new hash/signature algorithms through explicit governed policy while preserving the existing append-only chain.
