# USBAY Governance Dependency Map

This dependency map documents the phase 1 governance module boundaries.

## Runtime Modules

- `scripts/generate_ci_evidence_manifest.py`
  - Orchestrates CI evidence generation, verification, timestamping, chronology consensus, witness checks, and CLI execution.
  - Consumes boundary validators from `governance.*`.

- `governance.interfaces`
  - Defines typed governance result and data interfaces.
  - Contains no cryptographic operations and no file I/O.

- `governance.evidence`
  - Defines and validates evidence manifest shape.
  - Does not sign, hash files, or read secrets.

- `governance.trust_policy`
  - Defines and validates trust-policy shape.
  - Does not sign policies or access private key material.

- `governance.timestamping`
  - Defines and validates timestamp verification result shape.
  - Does not contact a TSA or parse private material.

- `governance.chronology`
  - Defines and validates chronology consensus shape.
  - Does not generate timestamp proofs or mutate audit logs.

- `audit.rfc3161_anchor`
  - Generates and verifies timestamp proofs.
  - Consumed by the CI governance script and immutable ledger paths.

- `audit.anchor`
  - Provides Ed25519 event signing and timestamp authority clients.
  - Must not log private key material.

## Dependency Direction

Allowed direction:

`CLI/runtime orchestration -> governance boundary validators -> typed interfaces`

`CLI/runtime orchestration -> audit cryptographic primitives`

Forbidden direction:

`governance boundary validators -> CLI/runtime orchestration`

`governance boundary validators -> private key material`

`governance boundary validators -> generated CI artifacts`

## Fail-Closed Control Points

- Missing or malformed trust policy: deny evidence generation.
- Trust-policy signature or audit continuity failure: deny evidence generation.
- Signer/public-key/fingerprint mismatch: deny evidence generation.
- Malformed evidence manifest: deny verification.
- Invalid timestamp verification metadata: deny timestamp acceptance.
- Malformed chronology consensus: deny chronology acceptance.

## Sensitive Data Constraints

The dependency graph intentionally keeps private key handling inside the
runtime signing path. Boundary modules operate only on public metadata, hashes,
validation results, and structured records.

