# Governance WORM Evidence Manifests

USBAY WORM evidence manifests prepare governance proof evidence for future immutable storage. This layer is deterministic and local only: it does not write to WORM storage, does not contact cloud storage, and does not create any durability claim by itself.

## Manifest Lifecycle

The manifest preparer verifies three upstream evidence artifacts:

- policy proof bundle
- local proof timestamp anchor
- RFC3161 timestamp preflight request

It then emits one deterministic manifest entry containing artifact type, creation timestamp, retention policy label, validation status, proof bundle hash, timestamp anchor hash, RFC3161 request digest, and governance module versions.

## Retention Label Model

Every manifest must include a `retention_policy_label`. The label is a governance assertion for future storage integration, such as `governance-retain-7y` or `legal-hold-review`. Missing retention labels fail closed with `WORM_RETENTION_POLICY_MISSING`.

## No-Storage Limitation

This module does not write to immutable storage and does not prove retention enforcement. It only prepares canonical evidence metadata for a future WORM writer. Operators must not treat a prepared manifest as proof that an object has been archived.

## Future Immutable Storage Integration

Future WORM integration should consume this manifest, write evidence objects to immutable storage, return storage provider object IDs, and verify replica hash continuity. That future layer must preserve redaction, fail-closed behavior, no raw payload export, and no fallback allow behavior.
