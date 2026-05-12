# Governance Signed Bundle Revocation Response Verification

USBAY supports deterministic local verification records for supplied OCSP or CRL response metadata associated with signed governance bundle LTV evidence. This layer does not fetch OCSP or CRL data and does not export raw certificates or raw revocation payloads.

## Lifecycle

1. Verify signed bundle LTV evidence.
2. Verify the OCSP or CRL revocation preflight record.
3. Create a response verification record from supplied metadata.
4. Bind the response to the preflight ID, LTV evidence ID, timestamp attachment ID, revocation source hash, TSA certificate fingerprint, trust-anchor fingerprint, validation policy, and retention label.
5. Verify the response record before using it as governance evidence.

## GOOD, REVOKED, UNKNOWN Model

Only `GOOD` responses can pass verification. `REVOKED` and `UNKNOWN` are deterministic fail-closed outcomes. Unknown or malformed statuses are treated as `REVOCATION_RESPONSE_STATUS_UNKNOWN`.

## Freshness And Time Bounds

`response_this_update_utc`, `response_next_update_utc`, and `checked_at_utc` must be UTC timestamps. `thisUpdate` must be before `nextUpdate`, and `checked_at_utc` must not precede `thisUpdate`. A response is stale if `checked_at_utc` is after `nextUpdate` or if the response age exceeds the freshness window declared by the preflight.

## Nonce And Replay Model

The response nonce hash is deterministically derived from the preflight ID, LTV evidence ID, and revocation source hash. This binds supplied response metadata to the preflight challenge without storing raw nonce material. Reusing an existing response ID is rejected as replay.

## Future Integration Path

Future live OCSP/CRL fetch support should run behind governed execution approval, store only response hashes and verification metadata, and continue using this response verification record as the local fail-closed boundary. Raw certificates, raw OCSP/CRL bytes, private keys, approval contents, and raw governance payloads must remain outside exported evidence.
