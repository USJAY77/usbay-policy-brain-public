# USBAY Governance Release Integrity

USBAY governance release integrity metadata proves that a release was built
from a deterministic governance baseline, a known commit lineage, the expected
governance dependency graph, and the active trusted CI evidence signer policy.

## Release Lifecycle

1. Build release integrity metadata with the canonical builder.
2. Include:
   - current commit and parent lineage
   - governance baseline tag
   - dependency graph hash
   - trust-policy fingerprint derived from canonical Ed25519 DER bytes
   - governance module version hashes
   - audit lineage metadata
3. Sign the canonical metadata payload.
4. Validate the metadata before release acceptance.

Unsigned, malformed, stale, drifted, or ambiguous release metadata fails
closed.

## Rollback Process

A rollback target is valid only when the previous release hash is explicitly
present in the allowed rollback target set supplied to validation. Rollback
metadata must preserve the previous release ID and previous release hash.

Invalid rollback targets, corrupted previous release hashes, or missing audit
lineage fail closed.

## Baseline Recovery

The governance baseline tag identifies the recovery anchor for release
metadata. Validation checks that the manifest baseline tag matches the expected
baseline and that the tag still resolves to the recorded commit. If a tag moves
unexpectedly, validation returns `release_integrity_tag_drift`.

If the baseline tag cannot be resolved, the builder records `UNRESOLVED`; a
later resolver that can resolve the tag will reject mismatched metadata.

## Integrity Guarantees

Release integrity validation enforces:

- canonical signed release metadata
- deterministic dependency graph consistency
- canonical DER public key fingerprint continuity
- governance module version continuity
- audit metadata continuity
- explicit rollback target authorization

The release integrity layer does not store private keys, generated release
artifacts, raw secrets, approval material, raw nonces, or private signing
material in the repository.

