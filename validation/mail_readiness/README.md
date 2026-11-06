# Governed Mail synthetic isolation — fixed startup and child no-exec gate

Synthetic harness only. No mail/application tests or product authority. Owner authorized implementation/publication and at most three evidence-backed new-head CI rounds for this execution-boundary repair; no unchanged retries, other permission widening, merge, deployment or activation.

## Fixed trusted startup

The original nonroot controller strictly inspects the actual x86-64 ELF Python executable and its sole PT_INTERP loader. It rejects malformed/ambiguous/truncated ELF metadata, unsafe paths, writable/set-ID/non-root-owned runtime objects and recursive interpreters. It records exact path, SHA256, device/inode, size and mode. There is no guessed loader fallback.

Within the existing isolated mount layout, the child recomputes the same binding and requires exact equivalence. Known /lib and /lib64 aliases are preserved so canonical paths retain their host semantics; other aliases fail. Runtime/source mounts remain read-only. Host-root ownership is checked before namespace mapping; inside the namespace, file identity/content is compared rather than falsely interpreting overflow ownership as host root.

Landlock permits only the exact Python and loader for the fixed, source-bound child startup. Git is not an execution target in this phase. No untrusted input, shell or caller-selected code is accepted by the startup protocol. The controller source and execution-boundary module must match the exact checked-out head in the privileged source check.

## Fresh-child gate

The fixed child imports trusted standard-library code, then installs an additional inherited seccomp filter before running any controls. It requires no_new_privs readback and seccomp filter mode. execve, execveat and alternate ABI routes are denied; non-x86-64 audit architectures are killed. Installation/readback failure is fatal. Existing parent syscall restrictions remain inherited and cannot be relaxed by the additive child filter.

The version2 exact-control contract requires all original ten controls plus execve denial, execveat denial and direct-loader-with-shell denial. The child also reports exact identity, empty supplementary groups and permanent group denial. Runtime-binding equivalence, fresh-gate evidence, every control and confirmed temporary mapping-policy restoration are mandatory for success.

## Scope and evidence limits

106 local pure tests passed. ELF metadata was read locally without installing filters or starting a child. This is not native CI equivalence or a complete security proof. Native results are pending at publication. Raw process output, environment and mail data are not audit evidence.

This trusted fixed-probe bootstrap is not a general arbitrary-code runner. Native in-process code, dynamic loading, full-suite command grammar and shared/persistent-runner threats need separate review. Existing full mail integration, release/provider authority and EGAP-HYDRA-REMOTE-TRANSPORT-AUTH gaps remain open. Synthetic PASS does not mean Governed Mail production readiness.

## Runtime artifact validation proposal (not yet executed)

`--runtime-artifacts` implies the fixed offline mail phase and adds exactly 30
synthetic cases from `runtime_artifact_contract.CASE_NAMES`. It tests the two
source-artifact modules; it does not start the gateway, issue an operational
release, establish a trust anchor or authorize execution.

The proposed hosted workflow adds a distinct dependency acquisition step inside
the nonprivileged controller. It downloads only binary wheels for
`cryptography==50.0.2`, `cffi==2.1.1` and `pycparser==3.11`, with all hashes taken
unchanged from the existing `staging/requirements-python311.lock`. Python 3.12
compatibility is unproven until native CI. Missing pip, compatible wheels or
matching hashes causes failure; there is no install/build or version fallback.

The root bootstrap independently recomputes the exact source and dependency
bindings before namespace launch. Dependencies are mounted read-only, nosuid,
nodev. Dynamic library loading remains necessary for cryptography; the existing
process-execution gates and executable allowlist are not widened. This is a
fixed trusted synthetic workload, not an exhaustive hostile-native-code sandbox.

The fresh child checks all 13 controls, identity, no-exec gate and source binding
before activating dependencies or importing crypto/product modules. It verifies
exact hashes, package versions and import origins, and proves the mount rejects
writes. Both source and dependency trees are rechecked after the fixed cases.
Test private keys are generated in memory and never serialized. Public synthetic
fixtures are disposable and do not establish operational producer authority.

Acceptance requires every fixed mail and runtime case to pass, complete bound
reports, every existing control, correct source/runtime identities and mapping
policy restoration. Report counts do not replace those checks. Only fixed case
identifiers, bounded outcomes and hashes are retained; no exception payloads or
package-manager output are published. Cache concurrency, gateway startup, full
scanner/provenance composition, producer build wiring and live mail/provider
behavior remain outside this test scope.

Publication, wheel acquisition and this native test execution require explicit
batch authorization. Do not infer it from earlier control-only or mail-only runs.

## Public-manifest packaging proposal (not yet native-tested)

The next prepared phase adds ten fixed pre-issued-manifest packaging cases to
`runtime_artifact_contract.CASE_NAMES` (40 artifact cases total). Existing 20
mail cases and all 13 controls remain required. Dependency pins and native
execution permissions are unchanged. The fixed export adds only
`security/runtime_artifact_package.py`; the Git-based producer is not exported.

`package_preissued_runtime_artifact` accepts an already signed public manifest,
independently supplied public verifier trust, and explicit expected source commit
and tree references. It verifies before creating output, copies only the declared
bytes into a new destination, rechecks source bytes, writes the public manifest
last and verifies the resulting package. It does not reconstruct Git history,
issue a manifest, select a producer trust anchor or authorize execution.
A failed copy can leave a partial destination; it is not automatically reused,
replaced or deleted. Reuse of an existing destination is rejected.

The proposed CLI accepts only `--source`, `--destination`, `--manifest-file`,
`--expected-source-commit` and `--expected-source-tree`. Verifier configuration
uses the existing public trust environment fields and explicit runtime mode.
The former private-key-file CLI is removed in this unpublished candidate; the
existing in-memory producer API is retained with its Git import deferred until
that API is called. Any external use of the old CLI must be checked before
migration; no active Replit configuration was changed.

A future build handoff requires independently governed issuance of the public
manifest and independent provisioning of verifier trust. The build must receive
expected source references from a verified source binding, choose a fresh output
root and ensure the actual runtime starts that exact package root. Packaging does
not provide release, provider, deployment or activation authority. A signed source
artifact does not replace the independent governance-release/startup checks.

No build/run hook is installed by this proposal. Full gateway module imports,
mutable-state directory mapping, scanner/provenance composition and live startup
need a separately bounded validation. No gateway-startup result follows from
these 40 artifact cases. Publication and the native round require explicit scope.

## Release-consumer integration proposal (native execution pending)

The next fixed phase adds 20 release-consumer cases (60 artifact/package/release
cases total), retaining 20 mail cases and all 13 controls. The static consumer
import closure is ten local modules and cryptography; no new dependency version,
Git permission, network permission or executable target is introduced.

The candidate connects deployment attestation to the existing shared, fresh
source-artifact verifier and requires explicit release-path selection in packaged
mode. Runtime read paths must not generate or repair a release. Production must
reject missing independent signing material and the development signing default.
Legacy Git parent/tag helpers reject packaged mode when build metadata is absent;
they must not guess lineage or execute Git as a fallback.

The public release reader now reuses the bounded regular-file/no-follow reader,
rejects duplicate fields at every JSON object level, and rejects NaN, Infinity and
numeric overflow. Previously accepted release-file symlinks or ambiguous JSON may
therefore be rejected. Missing/malformed reads keep the existing bounded error
contract. No runtime file is rewritten to recover from invalid evidence.

Native fixtures use generated-in-memory source-signing keys, public synthetic
policy snapshots and test-only HMAC release evidence. Configuration paths and
source-cache state are isolated per case; verifier/signature functions are not
mocked. Positive cases invoke the actual release startup-validation function.
These fixtures do not prove adopted policy signatures, enrolled real identities,
operational issuance, provider authority or production readiness.

The phase does not import gateway.app, start FastAPI, call providers, touch live
state or test the full scanner. Full gateway import/state mapping and the actual
build-package-to-runtime-root handoff remain separate requirements. Publication
and native execution require explicit batch authorization; preparation runs only
pure harness tests and source/patch checks locally.
