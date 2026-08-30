# Governance Policy Proof Bundles

USBAY policy proof bundles are deterministic, redacted audit artifacts for policy validation, simulation, and runtime parity evidence. They let operators export the evidence needed to prove that a policy preview matched runtime governance behavior without exposing raw request payloads, approval contents, secrets, or private keys.

## Bundle Lifecycle

The proof bundle exporter validates these inputs before writing an artifact:

- policy pack
- request context
- runtime decision evidence
- tenant and environment scope
- risk level and human approval requirement

The exporter computes canonical SHA256 hashes for the policy pack and request context, runs the policy simulator, verifies runtime parity, and writes a machine-readable bundle only if parity is verified. Unverified parity fails closed with `PROOF_PARITY_UNVERIFIED`.

## Export Contents

Each bundle includes:

- policy pack hash
- request context hash
- simulation decision
- runtime parity summary
- fail-closed status
- validation timestamp
- governance module versions
- redacted diagnostics summary

Raw payloads are intentionally excluded. Diagnostics are reduced to counts, decisions, hashes, scope identifiers, and failure codes.

## Operator Verification Flow

Use `scripts/governance_diagnostics.py export-policy-proof-bundle` to create a bundle and `verify-policy-proof-bundle` to validate it offline. `explain-proof-bundle` maps machine-readable proof errors to fail-closed operator guidance.

If a bundle is malformed, missing hash continuity, contains unsafe diagnostics, or cannot prove parity, verification returns a fail-closed result. Human approval may authorize remediation work, but the proof bundle verifier does not repair or reinterpret evidence.
