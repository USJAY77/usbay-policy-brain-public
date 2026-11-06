# Local pre-issued export intake

LOCAL_CANDIDATE / OBSERVATIONS_ONLY / NOT_ADOPTED / NO_EXPORT_AUTHORITY.

This read-only adapter composes the existing signed source verifier with the
existing V2 package/native timestamp verifier. It does not fetch artifacts,
extract archives, execute supplied source code, invoke a producer, issue a release,
load private signing material, change trust or call the operational exporter.
The existing operational workflow remains unchanged and its release-input gap
remains open until independently authorized inputs/integration are established.

This adapter's reference selection targets the current GitHub artifact workflow.
It is an Execution-side adapter, not a provider-independent governance contract.
The existing source and V2 cryptographic contracts remain unchanged and reusable;
other providers require their own explicit origin/reference adapter.

## Exact local layout

```
inputs/
  input_reference.json
  source/
    runtime_source_manifest.json
    <exact managed source files declared by that signed manifest>
  package/
    <exact 18-file V2 inventory>
```

No additional files or empty directories are accepted. Source and package roots,
directories, files, reference and manifests cannot be replaced by symlinks.
Files must be regular and singly linked. The source walk uses openat/O_NOFOLLOW
and descriptor-relative scandir, with no mutable-directory or dependency-prefix
exemptions. Bounds are 4,096 source files, 4,096 directories, depth 32, 4 MiB per
source file and 64 MiB total including its manifest. V2 retains its 2 MiB/file
and 32 MiB package bounds. Reference input is limited to 4 KiB.

## Independent public verifier inputs

The profile must be supplied separately, outside the input root, and is never
discovered in the artifact or inherited from the environment. Its schema is
`usbay.preissued_export_verifier_inputs.v1`. Exact fields are defined by
`PROFILE_FIELDS`; unknown fields, including authority/approval flags, fail closed.
It includes the existing exact V2 context bindings; source and package public
keys; explicit source verifier mode/scope; public TSA roots; evaluation time;
and bounded source/token/CRL freshness, skew and accuracy limits.

The exact `reference` schema is `usbay.preissued_export_reference.v1`: repository,
positive-decimal run/artifact IDs, tenant, source commit/tree, expected V2 manifest
SHA256 and expected source-manifest SHA256. These are selection/pinning inputs,
not provider-origin evidence or authorization. Reference bytes must be canonical.
Source `build_reference` must equal `github-actions:<run_id>`; this signed claim
still does not independently authenticate a provider run or download transport.

The signed source manifest must match the independently pinned bytes, expected
commit/tree and explicit public verifier key. Actual declared source file hashes,
sizes and modes are verified by `verify_runtime_artifact`. Source age is checked
against the explicit evaluation profile; the existing verifier also checks its
own manifest timestamp contract. The adapter does not reconstruct a Git commit
graph, prove that a claimed Git tree contains that file set, or validate a native
build. Those remain explicit requirements, even after source signatures pass.

V2 verifies signature/file coverage, exact context, canonical signature encoding,
real native timestamp/request/policy/chain/time and full-chain CRLs. The complete
input file inventory/identities and source/package bytes are rechecked afterwards.
Caller-owned profile dictionaries are snapshotted, preventing later rebinding.

## Local observation command

```
python -m audit.export_intake_v2 observe --inputs /absolute/inputs --profile /absolute/public-profile.json
```

Exit zero means `OBSERVED_ONLY_NOT_OPERATIONALLY_AUTHORIZED`, never export
readiness. Output contains scoped hashes, counts and explicit remaining
requirements, not raw message/source content, public certificate contents or
arbitrary exception text. Failures return exit one and a bounded DENY reason.
This observation command must not replace an operational attestation success gate.
The existing `require_operational_timestamp_verifier` denial remains unchanged.

## Authority and integration limits

Public verifier parameters are not adopted source, package-signer or TSA trust.
Valid observations do not establish provider origin, policy/identity authority,
revocation/replay recovery for an export, full audit/ledger/release/WORM semantics,
operational release authority, deployment or activation. The nested V2 remaining
requirements are preserved; the intake adds explicit origin/source/native-build,
release and point-of-use requirements. No governance record is registered or
modified. Human approval of this candidate cannot substitute for those controls.

Tests reuse genuine memory-only synthetic Ed25519/EC signing fixtures and native
OpenSSL verification. Their source references and provider IDs are synthetic;
they prove the bounded composition, not operational trust or real release issuance.
