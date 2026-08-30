# USBAY Key Management

## Policy Registry Keys

USBAY signs `governance/policy_registry.json` with an Ed25519 private key and verifies it at runtime with the matching public key.

## Private Key

- The policy private key must stay offline or in a human-controlled signing environment.
- The gateway must never load the private key.
- Production deployments should not ship `policy_private.key`.
- Humans sign policy releases with `POLICY_SIGNING_KEY` set in the signing shell, then run `scripts/sign_policy.py`.
- `scripts/sign_policy.py` does not read a default private-key file from the repository.

## Public Key

- The runtime gateway receives only `policy_public.key`.
- The gateway verifies `policy_registry.sig` over canonical sorted UTF-8 JSON.
- The runtime checks `policy_pubkey_id` against the configured allowlist.
- Revoked public key ids must be listed in the revocation list and fail closed.
- If public-key verification fails, USBAY fails closed.

## Rotation

1. Generate a new Ed25519 keypair with `scripts/gen_policy_keys.py`.
2. Human policy owner reviews and approves the registry.
3. Sign the registry with the new private key.
4. Add the new `policy_pubkey_id` to the allowlist.
5. Deploy the new public key and signature together.
6. Confirm `/policy/version` reports the intended registry version.

## Revocation

- Remove trust in a compromised public key by replacing it with a new approved public key.
- Add the compromised `policy_pubkey_id` to `revoked_policy_pubkey_ids`.
- Re-sign the current registry with the new private key.
- Restart or reload the gateway so it verifies the new signed registry.

## Emergency Fail-Closed

If the registry, public key, or signature is missing, stale, invalid, or unverifiable, the gateway must deny governance decisions or fail startup. No unsigned policy registry may be used for execution, simulation, or metadata governance.
