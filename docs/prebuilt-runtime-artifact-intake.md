# Prebuilt source artifact intake — non-production preparation

The source producer can run the existing packager in a separate clean Git
checkout before a platform publishing snapshot is made. The receiving build
checks the already issued package using public trust and mandatory source pins.
Neither that receiving check nor runtime verification requires Git or a signer.

Implemented: `security.runtime_artifact_build_check` reuses the existing artifact
authority loader, validates exact independently supplied commit/tree pins and
rechecks file integrity and public trust configuration. It writes no files and
does not generate keys, signatures, manifests, receipts or authority. Its return
value is immutable, non-authorizing metadata. Rechecking an old valid package
does not establish freshness, revocation/currentness or anti-rollback policy.

The producer and checker must be existing governed parts of the build toolchain.
Do not execute verifier code supplied only by the unverified incoming package.
Expected pins and producer public trust must come from the independently governed
build configuration, not be copied out of that package as acceptance criteria.

## Prepared receiving-build command

Run with the reviewed checker installation and existing public trust contract:

```sh
python3 -B -m security.runtime_artifact_build_check \
  --artifact-root .runtime-artifact \
  --expected-source-commit "${USBAY_RUNTIME_EXPECTED_SOURCE_COMMIT:?source commit required}" \
  --expected-source-tree "${USBAY_RUNTIME_EXPECTED_SOURCE_TREE:?source tree required}"
```

This is a proposed build-command substitution, not an active `.replit` change.
No download, archive extraction, signing, copying or automatic fallback is added.
The input directory must already contain the complete signed source package.
Runtime independently checks the package and all release, tenant, identity,
replay, policy, Hydra and audit requirements. Build acceptance does not authorize
execution, deployment or activation. Failure is a bounded error and nonzero exit.

## Gates that remain open

- Replit's supported transport of a prebuilt package into its publishing snapshot.
- Producer authorization, custody, independent public trust and exact source pins.
- The trusted build-checker installation and actual platform/image binding.
- Whole-artifact currentness/anti-rollback and complete operational startup.
- Existing PB routing, human reviews and remote transport authority.

Synthetic tests exercise the producer-to-receiver handoff after deleting the
producer checkout, using temporary repositories and ephemeral test keys. They
are supplementary engineering evidence, not platform validation or provisioning.

No active Replit app, live configuration, GitHub PR, trust or permissions are
changed by this isolated implementation.
