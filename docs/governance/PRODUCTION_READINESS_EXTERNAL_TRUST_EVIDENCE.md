# Production Readiness External Trust Evidence

USBAY remains an execution control layer. This contract verifies external trust
evidence metadata for production readiness without authorizing execution,
deployment, release, provider operation, or production activation.

Configuration is not verification. Connectivity is not evidence. Mocked tests,
fixtures, schemas, interfaces, and local adapters are not live external proof.
Only `EVIDENCE_VERIFIED` may satisfy an external trust requirement, and normal
repository tests must never produce `EVIDENCE_VERIFIED` for an enterprise
production environment using fixture providers.

## Capability States

- `NOT_CONFIGURED`
- `CONFIGURED`
- `CONNECTIVITY_VERIFIED`
- `EVIDENCE_VERIFIED`
- `BLOCKED`
- `INVALID`
- `UNAVAILABLE`

No state grants production authorization. The following flags remain false in
all outputs:

- `execution_allowed`
- `provider_execution`
- `production_activation`
- `deployment_authorized`
- `release_authorized`

## Provider Boundaries

RFC3161 timestamp authority integration records endpoint identity, trust-anchor
reference, nonce binding, message-imprint binding, certificate-chain hash,
policy OID, replay reference, freshness, and redacted timestamp evidence. Unit
tests use deterministic fixtures only and do not call a live TSA.

WORM/object-lock evidence storage records bucket/object references, object-lock
state, retention mode, retention window, legal hold, version id, immutable
checksums, readback verification, and blocked overwrite/delete/downgrade
attempts. Production evidence requires `COMPLIANCE` retention unless a separate
human-approved policy permits `GOVERNANCE`.

External signing records signer identity, key id, key version, approved
algorithm, trust-root reference, payload hash binding, nonce, signature hash,
revocation/expiry status, and verification evidence hash. Private keys,
certificates, tokens, and raw signature material must never be committed or
logged.

Regulator transport records a governed outbox state and can only progress when
schema, destination, approval, signature, RFC3161, WORM, idempotency, replay,
and redacted audit controls are present. Normal tests never contact regulator
endpoints.

Deployment evidence verifies evidence only. It records source commit,
provenance, SBOM reference, workflow identity, runner identity, target binding,
human authorization, signature/RFC3161/WORM references, final result,
freshness, replay protection, and rollback reference. It must never deploy.

## Live Verification

Live verification is deferred to a separate manual workflow or human terminal
operation with explicit configuration, protected environment approval, and
least-privilege credentials. Live output must include only provider identifier,
evidence hashes, fingerprints, verification result, verification time, and
failure code. Raw provider payloads, timestamp tokens, private material, access
tokens, secrets, and account identifiers are forbidden.

## Failure Behavior

Missing, malformed, stale, replayed, mismatched, sensitive, duplicated, or
uncertain evidence blocks. Missing regulator transport can be not applicable
only when policy explicitly proves regulator submission is not required.

Gateway and human policy remain authoritative.
