# Governance Signed Bundle Timestamps

Signed bundle timestamp attachments provide deterministic RFC3161-style timestamp evidence for signed USBAY auditor bundle envelopes.

## Timestamp Attachment Lifecycle

A timestamp attachment is prepared from an already signed auditor bundle envelope. The attachment stores:

- signed bundle ID
- canonical signed bundle hash
- SHA256 message imprint
- TSA policy identifier
- TSA serial number
- TSA generation time
- timestamp token hash
- verification scope
- retention label
- governance module versions

The attachment contains no raw governance payloads, private keys, approval contents, or TSA private material.

## RFC3161 Message Imprint Model

The signed bundle envelope is serialized as deterministic JSON and hashed with SHA256. The message imprint is the SHA256 hash of that signed bundle hash. This creates a stable, detached timestamp target suitable for future external RFC3161 submission without uploading the signed bundle contents.

## TSA Policy Validation Model

Local verification checks that the TSA policy identifier is syntactically valid and matches the expected policy. It also recomputes the deterministic token hash from the message imprint, policy identifier, serial number, generation time, and signed bundle ID.

Verification fails closed if the token is malformed, the policy is unexpected, the signed bundle hash mismatches, the attachment is replayed, or diagnostics are unsafe.

## Future External TSA Integration Path

This module is local and deterministic. Future integration can replace the deterministic token hash with detached RFC3161 token verification while preserving the same message imprint and attachment fields.
