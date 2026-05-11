# Runtime Provenance Bootstrap

`RuntimeProvenanceAuthority` is immutable, but it must be created from a deterministic bootstrap step first.

The bootstrap step canonicalizes GitHub Actions runtime state before release validation freezes the authority. This avoids repeated `git_commit_mismatch` drift caused by detached HEAD checkouts, synthetic PR merge commits, merge queue refs, replay/base runs, workflow dispatch, and push-to-main runs.

Bootstrap inputs:

- signed `governance_release.json`
- local checked-out `HEAD`
- `GITHUB_SHA`
- `GITHUB_HEAD_SHA`
- `GITHUB_BASE_SHA`
- trusted commit SHAs in `GITHUB_EVENT_PATH`
- available git parent links

The bootstrap resolver builds a deterministic accepted commit candidate set, validates ancestor continuity, and only then creates the immutable runtime provenance authority. If release lineage is unrelated to all trusted candidates, authority creation fails closed with `git_commit_mismatch`.

Diagnostics are available through `write_runtime_provenance_bootstrap_diagnostics(...)`, which writes `runtime_provenance_bootstrap.json` only when explicitly requested. The diagnostics include resolved commit candidates, continuity result, CI mode, event name, and rejected lineage checks. They do not include secrets, approval material, private keys, raw nonces, or raw evidence.

Downstream governance systems must not reinterpret GitHub runtime state. Tenant package generation, WORM archiving, RFC3161 timestamp generation, evidence indexes, verification reports, offline verification, and artifact attestation must consume the authority or the signed package manifest context produced from the authority.
