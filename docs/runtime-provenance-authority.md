# Runtime Provenance Authority

USBAY governance runtime uses a single immutable runtime provenance authority for release lineage decisions.

The authority is resolved once from `governance_release.json`, the signed release manifest, and the canonical CI normalization model. After creation, it is frozen and reused by export, reporting, verification, WORM, RFC3161, and package generation paths.

The authority contains:

- `release_hash`
- `policy_bundle_hash`
- `tenant_id`
- canonical normalized provenance context
- deterministic `authority_id`

Downstream systems must not reinterpret git state, detached HEAD state, merge commits, replay/base SHAs, or package-local release files independently. They must consume the authority object or a signed package manifest that was generated from that authority.

Fail-closed enforcement:

- missing authority where required rejects execution
- authority mismatch rejects execution
- release hash mismatch rejects execution
- policy bundle mismatch rejects execution
- tenant mismatch rejects execution
- provenance context mismatch rejects execution

CI normalization is permitted only inside authority resolution. The resolver may consider `GITHUB_SHA`, `GITHUB_HEAD_SHA`, `GITHUB_BASE_SHA`, checked-out HEAD, merge parents, and trusted GitHub event payload SHAs. Once the authority exists, downstream layers reuse its canonical context and do not reconstruct lineage.

This prevents recurring `git_commit_mismatch` drift between package generation, evidence indexing, report generation, WORM archiving, RFC3161 timestamping, offline verification, and GitHub artifact attestation.
