# USBAY Governance Dependency Map

This dependency map documents the phase 2 governance module boundaries and
dependency validation controls.

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

- `governance.dependencies`
  - Builds deterministic dependency graphs for governance boundary modules.
  - Fails closed on circular imports, forbidden cross-domain imports, and
    runtime governance coupling drift.

- `governance.telemetry`
  - Records audit-safe validation latency and artifact counts.
  - Does not serialize payload contents or private material.

- `audit.rfc3161_anchor`
  - Generates and verifies timestamp proofs.
  - Consumed by the CI governance script and immutable ledger paths.

- `audit.anchor`
  - Provides Ed25519 event signing and timestamp authority clients.
  - Must not log private key material.

## Dependency Direction

Allowed direction for enforced boundary modules:

`CLI/runtime orchestration -> governance boundary validators -> typed interfaces`

`CLI/runtime orchestration -> audit cryptographic primitives`

`governance.{evidence,chronology,timestamping,trust_policy} -> governance.interfaces`

Forbidden direction:

`governance boundary validators -> CLI/runtime orchestration`

`governance boundary validators -> private key material`

`governance boundary validators -> generated CI artifacts`

`governance.evidence -> governance.chronology`

`governance.chronology -> governance.evidence`

`governance.timestamping -> governance.trust_policy`

`governance.trust_policy -> scripts.*`

`governance.* -> audit.* | gateway.* | security.* | simulation_governance.*`

## Deterministic Boundary Graph

The enforced graph for the boundary modules is:

```text
governance.chronology  -> governance.interfaces
governance.evidence    -> governance.interfaces
governance.timestamping -> governance.interfaces
governance.trust_policy -> governance.interfaces
governance.interfaces  -> []
```

`governance.dependencies.validate_governance_dependency_map()` rejects:

- circular imports between governance domains
- imports that cross from one domain into another domain without an explicit
  allowlist entry
- imports from boundary modules into runtime, audit, gateway, security, or
  simulation code
- dependency graph hash drift when an expected graph hash is supplied

## Fail-Closed Control Points

- Missing or malformed trust policy: deny evidence generation.
- Trust-policy signature or audit continuity failure: deny evidence generation.
- Signer/public-key/fingerprint mismatch: deny evidence generation.
- Malformed evidence manifest: deny verification.
- Invalid timestamp verification metadata: deny timestamp acceptance.
- Malformed chronology consensus: deny chronology acceptance.
- Circular or forbidden governance dependency: deny production-readiness.
- Runtime coupling drift from boundary modules: deny production-readiness.

## Telemetry Metrics

Governance validation emits audit-safe metrics only:

- `validation_latency_ns`
- `trust_policy_validation_duration_ns`
- `timestamp_verification_duration_ns`
- `chronology_verification_duration_ns`
- `artifact_counts`

Metrics are aggregate measurements. They never include raw evidence contents,
private keys, secrets, nonces, approval material, or PEM private material.

## Sensitive Data Constraints

The dependency graph intentionally keeps private key handling inside the
runtime signing path. Boundary modules operate only on public metadata, hashes,
validation results, and structured records.
