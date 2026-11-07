# Release writer — actual consumer compatibility within synthetic scope

Status: LOCAL_COMPATIBILITY_VALIDATED / NOT_ADOPTED / NOT_DEPLOYED.

Baseline: USJAY77/usbay-policy-brain-public dc549b2167dc6bdbe8e5b1c988bb27e9176e388e,
tree b83475115eafe1ca75df661272958f21aac08665. Local candidate branch remains
local/release-owner-contract-v1. GitHub, Replit, Mac and serving state are not
asserted to match this candidate.

## Reproduced defect and correction

The initial writer signed seven scalar fields and a predecessor hash. The actual
unchanged security.deployment_attestation.validate_release_manifest requires
release_history for a non-GENESIS predecessor. The first direct consumer test
failed with rollback_lineage_ambiguous after HMAC/node/tenant/bundle checks;
native-compat-before-fix.txt retains the failure (one case, exit 1).

The corrected writer requires release_history as part of the exact approved
core. The Ed25519 authorization chain binds that complete core hash, and the
HMAC signature covers the same complete core. History is never appended after
authorization/signing, invented from a code default, or substituted by a hash.
Every supplied historical entry must match its chronological prefix and parent
hash, remain within the same tenant and nondecreasing time order, and verify
through the explicitly configured signer-verifier port. Historical GENESIS is
validated only at the pinned origin; this writer still cannot issue a current
GENESIS or adopt an origin. The authority source must independently establish
the applicability of the pinned lineage.

The supplied history is bounded to 32 entries and the existing 64 KiB parser
limit. Signature overhead is included in the pre-sign output-size bound, so a
committed output remains readable by reconciliation. This is an intentionally
bounded format; arbitrary older extra fields and historical signing-key custody
or rotation compatibility are not established.

The first expanded correction run had 62 writer cases plus one native case;
the native positive passed but the existing false-verifier test failed because
its stub now rejected the predecessor verification before reaching current
output verification. The stub was narrowed to return false for the current
core only, preserving its assertion that current output verification cannot
succeed on false. native-compat-first-correction.txt retains that failed run.
Two attempted source edits were rejected for patch-context mismatch before
changing files; the corrected edits then applied. They were not test passes.

## Actual unchanged consumer execution

Nine compatibility cases run the complete existing validate_release_manifest
function in separate local child processes. These are actual module imports
and calls, not extracted AST functions or substituted verifier implementations.
Imported origins and SHA256 bytes are checked for all five security modules:
deployment_attestation, node_identity, tenant_context, runtime_artifact_authority
and runtime_artifact_provenance. Their bytes remain equal to the pinned baseline.

Each child receives only an explicit minimal environment with task-owned
synthetic tenant/node fixtures and ephemeral ASCII HMAC material. Parent
environment variables and operational secrets are not inherited. No owner
private key or password is read. Child results record that gateway.app was not
imported. An installed Python audit hook rejects subprocess/exec and socket
connection/bind attempts; no kernel-wide network-isolation claim is made.

The tests pass explicit synthetic expected commit/bundle and provenance context,
with the accepted commit set restricted to the synthetic commit. Tenant and node
policies are synthetic; node mode is mock_local. This does not prove actual Git
ancestry, current policy-signature adoption, artifact provenance, hardware
attestation, live authority or release approval. No Gateway lifecycle is run.

| Actual consumer case | Observed result |
| --- | --- |
| Stored writer output with approved predecessor/history | PASS; HMAC valid; consumer release hash equals committed writer head |
| Second committed generation with full history | PASS; consumer release hash equals successor head |
| HMAC altered | DENY / release_signature_invalid |
| History removed and fixture re-signed | DENY / rollback_lineage_ambiguous |
| Predecessor changed and fixture re-signed | DENY / previous_release_hash_mismatch |
| Bundle changed and fixture re-signed | DENY / policy_bundle_hash_mismatch |
| Commit outside explicit accepted set | DENY / git_commit_mismatch |
| Future deployment time | DENY / deployment_timestamp_invalid |
| Unknown node | DENY / activating_node_unknown |

Negative-case re-signing uses only the isolated synthetic HMAC fixture. It is
not a writer grant or authority to alter a real release. Test manifest files
exist only inside task-owned temporary fixtures and are deleted by cleanup;
there is no deployment or external file/provider publication.

## Final combined validation and limits

Final suite: 135 owner-contract cases, 69 writer cases and 9 actual consumer
compatibility cases; 213 unique cases, zero failures/errors/skips on local Linux
Python 3.12. The writer cases retain thread/process contention and two actual
process-death boundaries. No packages installed. New compatibility tests are in
the existing governance-tier mapping; native CI itself was not dispatched.

compatibility-final-tests.txt retains exact IDs/results;
compatibility-final-result.json binds final source and unchanged consumer hashes;
compatibility-child-observations.json retains the nine bounded public consumer
observations. Historical 197-case results, pre-fix failure, first-correction
failure and earlier contract failures are retained separately.

Operational root/issuer/owner/status/signer adoption, independent currentness and
source/rollback anchors, production-grade authority fencing/recovery, external
signer idempotency, runtime wiring, immutable audit storage, actual provider/file
publication, macOS and CI/deployment validation remain OPEN. The configured
fixture ports establish no operational authority. HMAC verification establishes
cryptographic correspondence, not independent issuer identity or human review.

No source change to the existing consumer, Gateway, .replit, locks or workflow
files was made. No operational trust registration, commit/push, public upload,
workflow dispatch, restart, build or deployment was performed.
