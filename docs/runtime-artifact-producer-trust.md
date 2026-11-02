# Runtime artifact producer trust (development candidate)

This is a separate, fail-closed trust mechanism, not a startup integration,
deployment approval, or completed gitless repair. Existing Git-backed scanner,
release, tenant, replay, Hydra and audit controls remain unchanged.

## Contract and independent verifier configuration

`usbay.runtime_artifact_producer.v1` issues
`usbay.runtime_source_manifest.v1`, signed with existing cryptography Ed25519
primitives. The verifier never loads a private key or calls Git.

An operator must independently provision these public settings through an
approved configuration channel, not through the artifact being verified:

- `USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY`: canonical base64 of 32 raw bytes.
- `USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID`: `sha256:` plus lowercase SHA256 of
  those exact raw public-key bytes.
- `USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE`: `production` or `test`.
- `USBAY_ENV`: `production` (default) or `test`; a contradictory
  `USBAY_ENVIRONMENT` is rejected.

No settings have been provisioned by this change. Missing trust denies
verification. Production rejects test-scoped trusted identities and signed
test-scoped manifests. A verifier cannot mathematically discover whether an
operator has mislabeled a synthetic key as production: approving the correct
independent public key and scope is a human provisioning responsibility.

There is one explicitly trusted key at a time. Rotation requires an independently
authorized configuration update and a matching newly signed artifact. No
automatic discovery, bundled-key trust, TOFU or fallback to old/unknown keys.

## Producer and managed set

`security.runtime_artifact_builder.build_runtime_artifact_manifest` requires an
explicit Ed25519 private-key object, fingerprint and producer scope. It does not
load secrets, generate keys, write output, or invoke a publisher. Production
signing material must be provisioned separately; never package it in runtime.

The builder verifies a clean tracked Git worktree and records the exact HEAD
commit/tree and every regular tracked HEAD path with Git mode, SHA256 and size.
Observed source bytes must match the Git blob IDs. It rejects dirty sources,
symlinks, gitlinks, invalid paths and changing snapshots instead of omitting them.
The manifest covers a sorted complete managed inventory, its hash, schema,
producer identity/scope, optional build reference, timestamp and random ID.
The manifest digest and signature cover the declarations, not a bundled key.

The current producer supports committed regular source files only. Governed
generated artifacts require an explicit future contract; do not call this a
complete packaged-artifact producer until that closure has been established.
Ignored/untracked files never receive managed status. Existing runtime scanning
of unknown/generated/private material MUST remain; this verifier does not grant
unknown files an exception or independently authorize startup.

## Verification and limitations

Strict bounded UTF-8 JSON parsing rejects duplicate/unknown fields. Producer
fingerprint, independent trust, scope and Ed25519 signature are checked before
managed-file declarations are used. Source metadata, inventory hash and every
managed file are then verified. Linux openat/O_NOFOLLOW protects file and parent
traversal; inode/stat stability, regular type, size, Git executable mode and
SHA256 must match. An optional independently supplied expected commit/tree pin
must match the signed source identity.

The immutable `VerifiedRuntimeArtifact` result is the common future input for
both scanner and provenance resolver, not two separate authority roots. No
integration replaces their Git checks in this candidate.

No ordinary filesystem read is an immutable image boundary: a file can change
after verification. The packaging consumer must retain/verify the exact signed
snapshot at use. Whole-artifact replay/freshness policy, generated governed
files, unknown-file scanning integration and the actual publisher/image binding
remain separate requirements. A nonce alone does not prevent replay of an
unchanged, valid older manifest.

## Existing release HMAC risk

`security/deployment_attestation.py` currently falls back to fixed development
signing material when `USBAY_DEPLOYMENT_SIGNING_MATERIAL` is absent. Its
signature verification does not have a production-mode guard against this
fallback. This is a PROVEN static risk in the existing release path, not evidence
that production currently lacks a secret. The HMAC is NOT reused or enlarged to
authorize runtime artifact issuance. Changing existing release secret handling
is outside this patch.

## Validation boundary

The new standalone unittest suite imports only these producer/verifier modules,
standard-library utilities and existing cryptography. Synthetic keys stay in
memory; synthetic Git commits exist only in temporary test fixtures. Running it
does not load Gateway, project pytest fixtures or operational stores. Native
Gateway/provenance/scanner regressions remain required in a separately approved
isolated context; this suite is not a substitute for them.

PRODUCTION_PRODUCER_TRUST = NOT_PROVISIONED (by this task).
No deployment or activation is authorized. EGAP-HYDRA-REMOTE-TRANSPORT-AUTH = OPEN.
