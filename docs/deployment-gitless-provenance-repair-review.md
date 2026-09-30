# Gitless publish startup: provenance repair review

Status: **BLOCKED — design for human security review, not an implementation or production authorization.**

## Observed failure and scope

The most recent failed Autoscale publish recorded by the deployment service was build
`2b3aac77-42ed-43e2-bc83-580926e3f62d` on 2026-09-21. Dependency installation,
the build security scan, and image creation completed. The service then failed to
start: `validate_policy_registry_startup()` called
`validate_no_forbidden_runtime_files()`, and the scanner raised
`PolicyRegistryError("runtime_scan_git_index_unavailable")`. The `/` health probe
returned 500 and the service crash-looped. Replit publishing documentation says
Autoscale runtime images omit `.git`. The failed Git subprocess's underlying stderr
is not exposed, so the precise failed query is unknown.

Current development branch at review: `fix/runtime-scanner-managed-artifact-boundary`;
HEAD: `2223b56ee11533c4d7a380a4c52646ec318c1a8e`. This is not a
reconstruction of the failed image's exact source snapshot.

## Existing boundaries that must not be weakened

- `gateway/app.py` requires a canonical Git worktree, a real `.git` directory,
  and successful `git ls-files` (index) and `git ls-tree HEAD` queries. It compares
  the governed paths again after traversal to catch authority changes.
- Only paths proven **not** governed may receive narrow managed-runtime-artifact
  handling. Unknown provenance, symlinks, excluded directories, forged cache
  entries, private material, and traversal/read errors must continue to fail closed.
- `security/deployment_attestation.py` separately calls `current_git_commit()`
  while resolving the runtime provenance authority. Fixing only the scanner may
  expose a second production startup failure.
- The existing signed governance release manifest binds release/policy context;
  it is not a complete, independently attested index of shipped file paths and
  content hashes. A commit string, an environment variable, or an unsigned
  manifest shipped alongside mutable files is not an equivalent authority.
- Do not turn `runtime_scan_git_index_unavailable` into success; do not blanket
  exclude `.pythonlibs`, `__pycache__`, or other generated areas; do not make
  deployment readiness optimistic when provenance cannot be verified.

## Approval decision required before implementing

The owner/security reviewer must designate an **approved provenance producer and
verification trust root** for Gitless publishing. It must prove that the path
inventory and commit identity belong to the actual build being promoted and are
not merely self-declared by the same mutable runtime files. Decide whether the
publisher can preserve a trustworthy Git index/HEAD in the runtime image, or an
independent build/CI attestation must be supplied and verified. Confirm how the
attestation's signature/key rotation, replay prevention, release lineage, path
normalization, and shipped-file integrity will be enforced. Do not select a new
issuer, key, or production trust configuration by inference.

## Bounded implementation once approved

1. Define a versioned inventory contract and explicit verifier result. Bind
   normalized paths, file type/mode where relevant, content hashes, commit/tree
   identity, build/release identity, and attestation signature to the approved
   authority. Reject duplicate, absolute, parent-traversing, malformed, omitted,
   or conflicting paths and all invalid signatures. Retain only necessary
   metadata, never private-key material.
2. Obtain inventory and identity from a single verified snapshot for both the
   scanner and runtime provenance authority. In Git-backed development, retain
   the existing index/HEAD path and its consistency checks. In a Gitless image,
   accept **only** a verified approved attestation matching the shipped release;
   otherwise block startup. Do not silently fall back from a broken Git worktree
   to a lower-trust local file.
3. Compare the observed filesystem against the verified inventory before
   granting any managed-artifact exception; preserve the existing scan of unknown
   and generated content. Check for mutation during traversal. For files claimed
   as governed, verify content/mode against the attested inventory or reject.
   Ensure a mutable manifest cannot authorize itself or hide unexpected files.
4. Carry the same validated commit/release identity through
   `resolve_runtime_provenance_authority()`; keep signed release, policy, tenant,
   and lineage checks intact. If those checks still need Git, remain blocked
   rather than declaring the publisher fixed.
5. Restrict packaging/configuration changes to the chosen trusted build path;
   never introduce production credentials, new issuer material, or real customer
   data during development.

## Required isolated verification

- Positive: synthetic signed/attested inventory matches a Gitless publish-like
  filesystem; startup reaches the ordinary policy/readiness checks and does not
  falsely claim production readiness.
- Negative: missing/unsigned/forged/stale/replayed or wrong-build inventory;
  wrong commit/tree, wrong release or tenant, duplicate/ambiguous paths, changed
  content or file mode, new unexpected files, symlink escapes, and mutation during
  scan all block startup with content-safe diagnostics.
- Preserve all existing scanner Git-backed tests, including managed untracked
  paths, tracked files masquerading as managed, malformed Python caches, and
  fail-closed Git errors. Explicitly test that a broken `.git` directory is not
  treated as a legitimate Gitless deployment.
- Test the release-authority resolver in the same Gitless fixture and confirm
  default-deny export identity and existing FAIL_CLOSED/PBSEC readiness semantics.
- Only after a reviewed implementation: run a publish-like startup/health check
  and inspect the next publish logs. A local Preview 200 or a passing build alone
  is not evidence of successful production promotion.

## Open gaps

1. The failed image's Git subprocess stderr and exact source snapshot are not
   available from the exposed logs.
2. No approved Gitless file-inventory attestation producer/verifier or trust root
   has been identified in the current code.
3. No runtime change, test execution, commit, push, merge, deployment, or
   production authorization is performed by this review document.