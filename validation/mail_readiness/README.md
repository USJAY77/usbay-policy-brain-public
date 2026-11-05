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
