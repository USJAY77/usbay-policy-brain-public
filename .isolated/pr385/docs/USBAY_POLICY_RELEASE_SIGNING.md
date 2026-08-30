# USBAY Policy Release Signing

## Runtime Trust

USBAY Gateway runtime trust is Ed25519 only. The gateway verifies:

- `policy_registry.json` canonical JSON hash
- `policy_registry.sig` Ed25519 signature
- `policy_pubkey_id`
- key allowlist and revocation status in `governance/policy_key_config.json`
- policy validity and anti-rollback fields
- `policy_release_manifest.json` artifact hashes

The gateway must not load private keys and must not invoke GPG or PGP verification.

## Offline Release Signing

PGP/GPG may be used only by humans outside the gateway runtime to sign release artifacts:

- `policy_registry.json`
- `policy_registry.json.sig`
- `policy_release_manifest.json`

That offline signature is release evidence. It is not an alternate runtime trust path.

## Release Manifest

`governance/policy_release_manifest.json` must include:

- `policy_version`
- `policy_hash`
- `policy_pubkey_id`
- `created_at`
- `signed_by_human`
- `artifact_hashes`

`artifact_hashes` must include SHA-256 hashes for:

- `policy_registry.json`
- `policy_registry.json.sig`

## Fail-Closed Conditions

The gateway fails closed if:

- the Ed25519 policy signature is invalid
- `policy_pubkey_id` is unknown
- the signing key is revoked
- `policy_version` is missing
- the manifest hash does not match the release artifacts

## Custody Rules

- Keep policy private keys outside the repository.
- Store only public keys and key configuration in runtime.
- Do not log raw payloads, raw actor IDs, private keys, or secrets.
- Humans set and sign policy releases; the gateway only verifies and enforces them.
