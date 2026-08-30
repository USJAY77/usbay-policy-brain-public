# Governance RFC3161 Timestamp Preflight

USBAY RFC3161 timestamp preflight prepares governance proof bundles for future trusted timestamp authority integration without making network calls or accepting external TSA responses. The preflight output is deterministic local request material only.

## Preflight Lifecycle

The preflight module verifies a policy proof bundle and its local timestamp anchor, then emits:

- proof bundle hash
- timestamp anchor hash
- canonical request digest
- deterministic nonce
- requested policy OID placeholder
- redacted metadata summary
- governance module versions

The canonical request digest is the future RFC3161 messageImprint source. It is computed from hashes and redacted metadata only. Raw policy packs, request contexts, approval contents, private keys, and secrets are never included.

## No-Network Limitation

This layer does not call a TSA and does not verify TSA certificates, signatures, or revocation state. Any request material claiming a TSA response is rejected with `RFC3161_TSA_RESPONSE_UNVERIFIED`. Operators must treat this as preflight evidence, not a trusted external timestamp.

## Future TSA Verification Path

Future RFC3161 integration should submit only the canonical request digest or messageImprint to an external TSA. Returned timestamp tokens must be verified independently for token structure, messageImprint match, TSA signature, certificate chain, policy OID, revocation state, and timestamp continuity.

## Future WORM And Export Upgrade Path

The preflight request is designed to be embedded in signed export packages, WORM evidence manifests, and distributed chronology records. Those future layers must preserve fail-closed behavior, no raw payload export, no secret leakage, and deterministic verification.
