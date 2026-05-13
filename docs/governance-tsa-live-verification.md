# Governance TSA Live Verification Readiness

## Purpose

USBAY prepares signed governance evidence for future live TSA verification through deterministic local-only readiness stubs. The readiness layer verifies signed bundle timestamp attachments and emits hash-only planning records that can later be consumed by a governed external TSA integration.

This module does not contact real TSA services and does not perform network calls.

## Local-Only Verification Model

`governance/tsa_live_verification.py` validates existing signed bundle timestamp attachment metadata before any future live TSA flow is allowed. It verifies:

- timestamp attachment identity
- signed bundle hash binding
- SHA256 message imprint
- TSA policy ID
- TSA serial metadata
- TSA generation time
- timestamp token hash metadata
- local-only content-addressed output path

Readiness plans use this output path format:

```text
tsa-live://local-only/sha256/<timestamp_attachment_id>/<timestamp_token_hash>
```

## Fail-Closed Conditions

Verification fails closed when:

- the timestamp attachment is missing or invalid
- the message imprint is malformed
- the TSA policy ID is unexpected
- timestamp metadata is stale or malformed
- timestamp token hash metadata mismatches
- live verification output paths are mutable
- diagnostics contain unsafe material

## Sensitive Data Constraints

TSA live verification readiness diagnostics must remain redacted and hash-only. They must never include:

- raw governance payloads
- private keys
- approval contents
- raw OCSP or CRL bytes
- runtime artifacts
- TSA private material
- secrets or secret-like markers

## Future Integration Path

Future live TSA verification must be implemented in a separate governed capability branch. Any external TSA client must consume this verified hash-only readiness plan and preserve the same fail-closed checks before live network access is allowed.
