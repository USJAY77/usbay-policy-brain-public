# Governance WORM Immutable Storage Readiness

## Purpose

USBAY prepares sealed audit evidence for future WORM immutable storage through deterministic local-only readiness manifests. The readiness layer verifies sealed audit archive references and evidence record continuity before producing hash-only storage planning records.

This module does not write to real WORM storage, call cloud APIs, or export raw governance payloads.

## Local-Only Model

`governance/worm_immutable_storage.py` emits `LOCAL_ONLY` storage plans with content-addressed object paths in this form:

```text
worm://local-only/sha256/<archive_root_hash>/<storage_object_id>
```

The manifest contains hashes and identifiers only:

- sealed archive ID
- archive root hash
- evidence record ID
- evidence record chain hash
- immutable storage manifest hash
- append-only manifest entry hashes
- replay binding hashes
- retention policy label

## Fail-Closed Conditions

Verification fails closed when:

- the sealed archive root hash is missing or invalid
- the evidence record chain is missing or not bound to the archive
- manifest entries are reordered
- an archive ID is planned more than once
- output paths are mutable or not content-addressed
- manifest hashes mismatch
- diagnostics contain unsafe material

## Sensitive Data Constraints

WORM immutable storage readiness diagnostics must remain redacted and hash-only. They must never include:

- raw governance payloads
- private keys
- approval contents
- raw OCSP or CRL bytes
- runtime-generated artifacts
- secrets or secret-like markers

## Future Integration Path

Future external WORM integrations must consume this verified hash-only plan and preserve the same fail-closed checks before any storage write occurs. Cloud or storage-provider APIs remain outside this readiness layer until explicitly governed by a separate one-capability branch and PR.
