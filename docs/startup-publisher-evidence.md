# Bounded synthetic startup and publisher evidence

This development harness does not publish, provision production trust, authorize
execution, contact nodes, or assert provider support. The exact starting candidate
is commit `9bb15226a0964f2675c5077cdc7ed28c94909a42`, tree
`f8d20179dc0eeca5b166b04be7251ea90e93767a`.

## Source, build and artifact boundaries

The runner retains the previous bounded suites and source-copy validation.
Separately, it reconstructs the exact candidate from locally available Git blob
bytes/modes and original commit/tree objects in a new temporary object repository.
It copies no original Git configuration, remotes, credentials or hooks. Ancestor
history is not required for this packaging test. It does not invent a commit ID,
change the app repository, fetch objects or execute downloaded code.

The actual candidate builder requires a working Git executable, `.git` directory,
index, HEAD/tree, complete regular tracked inventory, matching blobs/modes and
clean tracked source. Symlinks, gitlinks, source mutation and unsupported paths
must fail closed. The build-only producer takes an explicitly supplied in-memory
synthetic signing key, key fingerprint and test scope. Production CLI inputs
remain an explicit external build-only signing-key file and independently
approved producer key ID/scope; no key is provisioned by this validation.

The candidate package contains every tracked regular source file, preserving
executable modes, plus its signed manifest, without `.git`, ignored state,
dependency directories or private build input. Local negative boundary cases
exercise missing Git executable/index, dirty bytes, mode change and symlink.
This is an emulated build context, not evidence of Replit publisher support.
The configured `.replit` profile invokes packaging before the production run;
the mere configuration does not prove what files/Git metadata a publisher sees.

An independently recomputed canonical inventory of packaged files AND the signed
manifest receives a content-addressed SHA-256 identity. `artifact-binding.json`
links the exact commit/tree, signed manifest, inventory digest and a clearly
synthetic local deployment reference. This is not a container image, actual
deployment, immutable filesystem, human authorization, anti-rollback decision,
or provider attestation. The inventory excludes separately configured runtime
dependencies and synthetic external governance fixtures; full image closure
therefore remains PARTIAL.

## Remaining startup validation

New focused tests run against the exact candidate package, with Git unavailable
and subprocesses denied. Synthetic signed registry/pinned public-key/release and
separation-of-duty fixtures reside outside the package. Private test keys remain
in memory. Existing validators are called unchanged: observer wrappers record
entry/completion but never return fabricated success. Synthetic role labels are
not actual human approvals.

The new test module requires the runner's explicit opt-in and separate gitless
package directory before importing the app. Ordinary collection elsewhere
reports an unsupported-context skip and must not touch real audit/replay state.
The runner defaults to every bounded phase; an explicit comma-separated second
argument can select a clearly recorded targeted rerun. Targeted reruns do not
claim that unselected suites were executed again.

The real lifespan runs scanner, provenance, tenant loading, replay policy,
Hydra role/node prerequisites, release integrity, runtime governance monitor,
an existing empty-genesis ledger, policy registry and final artifact freshness.
Negative cases must reject invalid tenant input, fail-open replay config, Hydra
role changes, corrupt ledger, invalid policy signature, revoked key and authority
mismatch. Existing source policy is not widened to advance startup.

Persistent nonce-store initialization, missing/corrupt store and reopen/replay
behavior are tested separately using the real local store API. The current
startup only validates replay policy: it does NOT initialize that store.
Successful lifespan must not manufacture request identity: the default
evidence-export identity verifier remains unavailable. These observations do
not establish request authentication or remote transport authorization.

## Governance and external evidence still required

Actual publisher Git-backed build-context availability, runtime dependency/image
closure, true deployment-to-image/source binding, trusted production producer
and release materials, externally controlled runtime configuration, durable audit
storage, whole-artifact freshness and human production approval require separate
evidence. Tests do not supply these production inputs. An unavailable real input
must remain BLOCKED, never be represented as a synthetic production approval.

All results must be reported from captured logs rather than this test plan.
PRODUCTION_TRUST_PROVISIONED_BY_THIS_TASK = false
DEPLOYMENT_AUTHORIZED = false
ACTIVATION_AUTHORIZED = false
EGAP-HYDRA-REMOTE-TRANSPORT-AUTH = OPEN
